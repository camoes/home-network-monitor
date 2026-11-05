#!/usr/bin/env python3
"""Prometheus exporter for WAN counters exposed by a ZTE F6600P web UI.

Credentials are read from a mounted, mode-0600 router.env file; they are never
part of the image, command line, metrics, or logs.
"""

from __future__ import annotations

import csv
import hashlib
import http.server
import json
import os
import threading
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from http.cookiejar import CookieJar
from pathlib import Path

CONFIG_FILE = Path(os.getenv("ROUTER_ENV_FILE", "/run/secrets/router.env"))
DEVICE_OVERRIDES_FILE = Path(os.getenv("DEVICE_OVERRIDES_FILE", "/run/secrets/device-overrides.csv"))
PORT = int(os.getenv("ROUTER_EXPORTER_PORT", "9800"))
_CLIENT_LOCK = threading.Lock()
_ROUTER_CLIENT: "ZTEClient | None" = None
_ROUTER_CONFIG_KEY: tuple[str, str, str, str] | None = None
_RETRY_AFTER = 0.0
_FAILURE_COUNT = 0


def read_config() -> dict[str, str]:
    values: dict[str, str] = {}
    for line in CONFIG_FILE.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def apply_device_overrides(devices: list[dict[str, str]]) -> list[dict[str, str]]:
    """Apply local MAC-to-name/type labels without putting household data in Git."""
    try:
        with DEVICE_OVERRIDES_FILE.open(encoding="utf-8", newline="") as handle:
            overrides = {
                (row.get("mac") or "").strip().upper().replace("-", ":"): row
                for row in csv.DictReader(handle)
                if (row.get("mac") or "").strip()
            }
    except OSError:
        return devices
    for device in devices:
        row = overrides.get(device.get("mac", "").upper())
        if row:
            if (row.get("name") or "").strip():
                device["name"] = row["name"].strip()
            if (row.get("device_type") or "").strip():
                device["device_type"] = row["device_type"].strip()
    return devices


def prom_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


class ZTEClient:
    def __init__(self, config: dict[str, str]):
        self.base_url = config["ROUTER_URL"].rstrip("/")
        self.username = config["ROUTER_USERNAME"]
        self.password = config["ROUTER_PASSWORD"]
        self.wan_name = config.get("ROUTER_WAN_NAME", "FTTH-Data")
        self.guid = int(time.time() * 1000)
        self.logged_in = False
        self._reset_session()

    def _reset_session(self) -> None:
        self.cookies = CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookies)
        )
        self.opener.addheaders = [
            ("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36"),
            ("X-Requested-With", "XMLHttpRequest"),
            ("Referer", self.base_url + "/"),
        ]

    def _next_guid(self) -> int:
        self.guid += 1
        return self.guid

    def _request(self, path: str, data: bytes | None = None) -> bytes:
        headers = {"Content-Type": "application/x-www-form-urlencoded"} if data is not None else {}
        request = urllib.request.Request(self.base_url + path, data=data, headers=headers)
        with self.opener.open(request, timeout=10) as response:
            return response.read()

    def login(self) -> None:
        # Start with fresh cookies so reauthentication cannot reuse an expired session.
        self._reset_session()
        self.logged_in = False
        # Initialize the router's session cookie, then obtain its per-login tokens.
        self._request("/")
        entry = self._request("/?_type=loginData&_tag=login_entry")
        session_info = json.loads(entry.decode("utf-8"))
        session_token = session_info.get("sess_token")
        if not session_token or int(session_info.get("lockingTime", 0) or 0) != 0:
            raise RuntimeError("Router did not issue a login session token")

        token_path = f"/?_type=loginData&_tag=login_token&_={self._next_guid()}"
        token_xml = ET.fromstring(self._request(token_path))
        login_token = (token_xml.text or "").strip()
        if not login_token:
            raise RuntimeError("Router returned an empty login challenge")

        password_hash = hashlib.sha256((self.password + login_token).encode("utf-8")).hexdigest()
        form = urllib.parse.urlencode({
            "action": "login",
            "Password": password_hash,
            "Username": self.username,
            "_sessionTOKEN": session_token,
        }).encode("ascii")
        login_path = f"/?_type=loginData&_tag=login_entry&_={self._next_guid()}"
        result = json.loads(self._request(login_path, form).decode("utf-8"))
        if int(result.get("lockingTime", 0) or 0) != 0 or result.get("loginErrMsg"):
            raise RuntimeError("Router rejected the saved login")
        if result.get("login_need_refresh") == 1:
            self._request("/")
        self.logged_in = True

    def wan_counters(self, retry_session: bool = True) -> dict[str, int | str]:
        view = f"/?_type=menuView&_tag=ethWanStatus&Menu3Location=0&_={self._next_guid()}"
        self._request(view)
        data = (
            f"/?_type=menuData&_tag=wan_internetstatus_lua.lua"
            f"&TypeUplink=2&pageType=1&_={self._next_guid()}"
        )
        root = ET.fromstring(self._request(data))
        error = (root.findtext("IF_ERRORSTR") or "").strip()
        if error and error not in {"SUCC", "SUCCESS", "OK"}:
            if "SessionTimeout" in error and retry_session:
                self.login()
                return self.wan_counters(retry_session=False)
            raise RuntimeError("Router returned an error for the WAN status query")

        instances = root.findall("ID_WAN_COMFIG/Instance")
        if not instances:
            instances = root.findall(".//Instance")
        for instance in instances:
            fields = list(instance)
            values: dict[str, str] = {}
            for index in range(0, len(fields) - 1, 2):
                name = (fields[index].text or "").strip()
                value = (fields[index + 1].text or "").strip()
                if name:
                    values[name] = value
            if values.get("WANCName") != self.wan_name:
                continue
            counters: dict[str, int | str] = {
                "connection": self.wan_name,
                "up": 1 if values.get("ConnStatus") == "Connected" else 0,
            }
            for source, target in (
                ("RxBytes", "rx_bytes"),
                ("TxBytes", "tx_bytes"),
                ("RxPackets", "rx_packets"),
                ("TxPackets", "tx_packets"),
                ("ErrorsReceived", "rx_errors"),
                ("ErrorsSent", "tx_errors"),
            ):
                raw = values.get(source)
                if raw is not None and raw.isdigit():
                    counters[target] = int(raw)
            required = {"rx_bytes", "tx_bytes", "rx_packets", "tx_packets"}
            if not required.issubset(counters):
                raise RuntimeError("Selected WAN row did not include byte and packet counters")
            return counters
        raise RuntimeError(f"Configured WAN connection was not present: {self.wan_name}")

    def _menu_data(self, tag: str, node_name: str, retry_session: bool = True) -> list[dict[str, str]]:
        view = f"/?_type=menuView&_tag=localNetStatus&Menu3Location=0&_={self._next_guid()}"
        self._request(view)
        data = f"/?_type=menuData&_tag={tag}&_={self._next_guid()}"
        root = ET.fromstring(self._request(data))
        error = (root.findtext("IF_ERRORSTR") or "").strip()
        if error and error not in {"SUCC", "SUCCESS", "OK"}:
            if "SessionTimeout" in error and retry_session:
                self.login()
                return self._menu_data(tag, node_name, retry_session=False)
            raise RuntimeError("Router returned an error for the device query")

        wlanap_map: dict[str, str] = {}
        for ap in root.findall("OBJ_WLANAP_ID/Instance"):
            fields = list(ap)
            pairs = {
                (fields[i].text or "").strip(): (fields[i + 1].text or "").strip()
                for i in range(0, len(fields) - 1, 2)
            }
            if pairs.get("_InstID") and pairs.get("ESSID"):
                wlanap_map[pairs["_InstID"]] = pairs["ESSID"]

        instances = root.findall(f"{node_name}/Instance")
        if not instances and root.get("format") == "json":
            instances = [inst for node in root if node.tag != "OBJ_WLANAP_ID" for inst in node.findall("Instance")]
        devices: list[dict[str, str]] = []
        for instance in instances:
            fields = list(instance)
            values = {
                (fields[i].text or "").strip(): (fields[i + 1].text or "").strip()
                for i in range(0, len(fields) - 1, 2)
            }
            mac = values.get("MACAddress") or values.get("PhysAddress") or ""
            if not mac:
                continue
            port = values.get("AliasName") or values.get("Layer1Interface") or ""
            ssid = values.get("SSIDName") or values.get("SSID") or ""
            if port in wlanap_map:
                # AliasName on this firmware is the AP object (DEV.WIFI.AP1) and
                # OBJ_WLANAP_ID maps it to the ESSID actually in use.
                ssid = ssid or wlanap_map[port]
                port = port.replace("DEV.WIFI.", "")
            icon = values.get("IconType", "")
            type_names = {
                "DesktopComputer": "ordenador",
                "laptop": "portátil",
                "smartphone": "móvil",
                "game": "consola",
                "stb": "TV/decodificador",
                "camera": "cámara",
            }
            active = values.get("Active", "1").lower() in {"1", "true", "yes"}
            if not active:
                continue
            devices.append({
                "mac": mac.upper(),
                "ip": values.get("IPAddress", ""),
                "name": values.get("HostName") or values.get("AliasName") or mac.upper(),
                "device_type": type_names.get(icon, icon or "desconocido"),
                "network": "WLAN" if node_name == "OBJ_WLAN_AD_ID" else "LAN",
                "port": port,
                "ssid": ssid,
            })
        return devices

    def connected_devices(self) -> list[dict[str, str]]:
        lan = self._menu_data("accessdev_landevs_lua.lua", "OBJ_ACCESSDEV_ID")
        wlan = self._menu_data("wlan_client_stat_lua.lua", "OBJ_WLAN_AD_ID")
        # A device can appear in both lists on some firmware; MAC + network keeps
        # the records distinct while avoiding exact duplicate rows.
        unique: dict[tuple[str, str], dict[str, str]] = {}
        for device in lan + wlan:
            unique[(device["mac"], device["network"])] = device
        return list(unique.values())


def render_metrics() -> str:
    global _ROUTER_CLIENT, _ROUTER_CONFIG_KEY, _RETRY_AFTER, _FAILURE_COUNT
    try:
        config = read_config()
    except OSError:
        config = {}
    configured = all(config.get(key) for key in ("ROUTER_URL", "ROUTER_USERNAME", "ROUTER_PASSWORD"))
    lines = [
        "# HELP router_exporter_configured 1 when router credentials are configured.",
        "# TYPE router_exporter_configured gauge",
        f"router_exporter_configured {1 if configured else 0}",
        "# HELP router_exporter_scrape_success 1 when the last router query succeeded.",
        "# TYPE router_exporter_scrape_success gauge",
    ]
    if not configured:
        lines.append("router_exporter_scrape_success 0")
        return "\n".join(lines) + "\n"

    config_key = (
        config["ROUTER_URL"],
        config["ROUTER_USERNAME"],
        config["ROUTER_PASSWORD"],
        config.get("ROUTER_WAN_NAME", "FTTH-Data"),
    )
    if time.monotonic() < _RETRY_AFTER:
        lines.append("router_exporter_scrape_success 0")
        return "\n".join(lines) + "\n"

    try:
        with _CLIENT_LOCK:
            if _ROUTER_CONFIG_KEY != config_key or _ROUTER_CLIENT is None:
                _ROUTER_CLIENT = ZTEClient(config)
                _ROUTER_CONFIG_KEY = config_key
                _FAILURE_COUNT = 0
                _RETRY_AFTER = 0.0
            if not _ROUTER_CLIENT.logged_in:
                _ROUTER_CLIENT.login()
            counters = _ROUTER_CLIENT.wan_counters()
            try:
                devices = apply_device_overrides(_ROUTER_CLIENT.connected_devices())
                device_inventory_ok = True
            except Exception:
                devices = []
                device_inventory_ok = False
            _FAILURE_COUNT = 0
            _RETRY_AFTER = 0.0
    except Exception:
        # Avoid leaking router responses or credentials to Prometheus or logs.
        _FAILURE_COUNT += 1
        _RETRY_AFTER = time.monotonic() + min(300, 30 * (2 ** min(_FAILURE_COUNT - 1, 4)))
        if _ROUTER_CLIENT is not None:
            _ROUTER_CLIENT.logged_in = False
        lines.append("router_exporter_scrape_success 0")
        return "\n".join(lines) + "\n"

    connection = prom_label(str(counters["connection"]))
    labels = f'{{connection="{connection}"}}'
    lines.append("router_exporter_scrape_success 1")
    lines.extend((
        "# HELP router_device_inventory_scrape_success 1 when the router device inventory query succeeded.",
        "# TYPE router_device_inventory_scrape_success gauge",
        f"router_device_inventory_scrape_success {1 if device_inventory_ok else 0}",
        "# HELP router_connected_devices Number of active devices reported by the router.",
        "# TYPE router_connected_devices gauge",
    ))
    for network in ("LAN", "WLAN"):
        count = sum(1 for device in devices if device["network"] == network)
        lines.append(f'router_connected_devices{{network="{network}"}} {count}')
    lines.extend((
        "# HELP router_connected_device_info Connected device metadata from the router; value is always 1.",
        "# TYPE router_connected_device_info gauge",
    ))
    for device in devices:
        device_labels = {
            "mac": device.get("mac", ""),
            "ip": device.get("ip", ""),
            "name": device.get("name", ""),
            "device_type": device.get("device_type", "desconocido"),
            "network": device.get("network", ""),
            "port": device.get("port", ""),
            "ssid": device.get("ssid", ""),
        }
        rendered = ",".join(f'{key}="{prom_label(value)}"' for key, value in device_labels.items())
        lines.append(f"router_connected_device_info{{{rendered}}} 1")
    for name, help_text, key in (
        ("router_wan_connection_up", "Whether the configured WAN connection is up (1) or down (0).", "up"),
        ("router_wan_received_bytes_total", "Cumulative WAN bytes received from the Internet.", "rx_bytes"),
        ("router_wan_transmitted_bytes_total", "Cumulative WAN bytes sent to the Internet.", "tx_bytes"),
        ("router_wan_received_packets_total", "Cumulative WAN packets received from the Internet.", "rx_packets"),
        ("router_wan_transmitted_packets_total", "Cumulative WAN packets sent to the Internet.", "tx_packets"),
        ("router_wan_receive_errors_total", "Cumulative WAN receive errors.", "rx_errors"),
        ("router_wan_transmit_errors_total", "Cumulative WAN transmit errors.", "tx_errors"),
    ):
        lines.extend((f"# HELP {name} {help_text}", f"# TYPE {name} counter" if name.endswith("_total") else f"# TYPE {name} gauge"))
        lines.append(f"{name}{labels} {counters.get(key, 0)}")
    return "\n".join(lines) + "\n"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path == "/health":
            body = b"ok\n"
            status = 200
            content_type = "text/plain; charset=utf-8"
        elif self.path == "/metrics":
            body = render_metrics().encode("utf-8")
            status = 200
            content_type = "text/plain; version=0.0.4; charset=utf-8"
        else:
            body = b"not found\n"
            status = 404
            content_type = "text/plain; charset=utf-8"
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    print(f"ZTE WAN exporter listening on :{PORT}", flush=True)
    http.server.ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
