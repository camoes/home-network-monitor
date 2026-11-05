#!/usr/bin/env python3
"""AdGuard Home DNS query collector + LAN inventory -> SQLite -> geo map.

Data flow:
  AdGuard Home /control/querylog  -> queries (per client IP, per domain)
  router-exporter /metrics        -> devices (name, MAC, IP, band/SSID)
  ip-api.com (batched, cached)    -> approximate location of public endpoints

Nothing leaves the LAN except DNS names' destination IPs, and only if a local
GeoIP database is not supplied (see GEOIP_API=off).
"""

from __future__ import annotations

import base64
import csv
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import classify

ADGUARD_URL = os.getenv("ADGUARD_URL", "http://host.docker.internal:80").rstrip("/")
ROUTER_EXPORTER_URL = os.getenv("ROUTER_EXPORTER_URL", "http://router-exporter:9800/metrics")
DB_PATH = Path(os.getenv("DB_PATH", "/data/netviz.db"))
OUI_PATH = Path(os.getenv("OUI_PATH", "/data/oui.csv"))
HTTP_PORT = int(os.getenv("HTTP_PORT", "8080"))
POLL_SECONDS = int(os.getenv("POLL_SECONDS", "60"))
QUERYLOG_LIMIT = int(os.getenv("QUERYLOG_LIMIT", "2000"))
SECRETS_FILE = Path(os.getenv("ADGUARD_ENV_FILE", "/run/secrets/adguard.env"))
OVERRIDES_FILE = Path(os.getenv("DEVICE_OVERRIDES_FILE", "/run/secrets/device-overrides.csv"))
STATIC_DIR = Path(os.getenv("STATIC_DIR", "/app/static"))
GEOIP_API = os.getenv("GEOIP_API", "ip-api").lower()  # ip-api | off
HOME_FILE = Path(os.getenv("HOME_FILE", "/data/home.json"))

_LOCK = threading.RLock()
_CONN: sqlite3.Connection | None = None
_OUI: dict[str, str] = {}
_OVERRIDES: dict[str, dict[str, str]] = {}
_LAST: dict[str, str] = {}


def prom_label(value: str) -> str:
    """Escape a Prometheus label value."""
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


# ---------------------------------------------------------------- persistence
SCHEMA = """
CREATE TABLE IF NOT EXISTS queries (
    id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    client_ip TEXT NOT NULL,
    client_mac TEXT,
    client_name TEXT,
    client_type TEXT,
    domain TEXT NOT NULL,
    qtype TEXT,
    dest_ip TEXT,
    dest_kind TEXT,
    country TEXT,
    city TEXT,
    lat REAL,
    lon REAL,
    org TEXT,
    blocked INTEGER DEFAULT 0,
    filtered INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_queries_ts ON queries(ts);
CREATE INDEX IF NOT EXISTS idx_queries_dest ON queries(dest_ip);
CREATE INDEX IF NOT EXISTS idx_queries_client ON queries(client_mac);
CREATE TABLE IF NOT EXISTS devices (
    mac TEXT PRIMARY KEY,
    ip TEXT,
    name TEXT,
    device_type TEXT,
    vendor TEXT,
    network TEXT,
    port TEXT,
    ssid TEXT,
    last_seen TEXT,
    source TEXT
);
CREATE TABLE IF NOT EXISTS geo (
    ip TEXT PRIMARY KEY,
    ok INTEGER,
    country TEXT,
    city TEXT,
    lat REAL,
    lon REAL,
    org TEXT,
    ts TEXT
);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
"""


def db() -> sqlite3.Connection:
    global _CONN
    with _LOCK:
        if _CONN is None:
            DB_PATH.parent.mkdir(parents=True, exist_ok=True)
            _CONN = sqlite3.connect(DB_PATH, check_same_thread=False)
            _CONN.row_factory = sqlite3.Row
            _CONN.execute("PRAGMA journal_mode=WAL")
            _CONN.executescript(SCHEMA)
            _migrate_queries(_CONN)
            _CONN.commit()
        return _CONN


def _migrate_queries(conn: sqlite3.Connection) -> None:
    """Add the per-query client identity columns (no guessing on old rows).

    DHCP reassigns addresses on router reboots, so attributing history by IP is
    wrong: identity must be frozen when the query is ingested. Legacy rows keep
    client_mac NULL and are labelled by their IP instead of a guessed device.
    """
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(queries)")}
    for column in ("client_mac", "client_name", "client_type"):
        if column not in columns:
            conn.execute(f"ALTER TABLE queries ADD COLUMN {column} TEXT")


def meta_set(key: str, value: str) -> None:
    with _LOCK:
        db().execute("INSERT INTO meta(k, v) VALUES(?, ?) "
                     "ON CONFLICT(k) DO UPDATE SET v=excluded.v", (key, value))
        db().commit()


def meta_get(key: str, default: str = "") -> str:
    row = db().execute("SELECT v FROM meta WHERE k=?", (key,)).fetchone()
    return row["v"] if row else default


# ------------------------------------------------------------------- settings
def read_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return values
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def refresh_static_data() -> None:
    global _OUI, _OVERRIDES
    _OVERRIDES = classify.load_overrides(OVERRIDES_FILE)
    _OUI = classify.load_oui(OUI_PATH)


# --------------------------------------------------------------------- AdGuard
def adguard_get(path: str, timeout: int = 20) -> dict:
    creds = read_env_file(SECRETS_FILE)
    headers = {"Accept": "application/json"}
    user, password = creds.get("AGH_USER", ""), creds.get("AGH_PASS", "")
    if user or password:
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        headers["Authorization"] = f"Basic {token}"
    request = urllib.request.Request(ADGUARD_URL + path, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def is_public(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        address.is_private or address.is_loopback or address.is_link_local
        or address.is_multicast or address.is_reserved or address.is_unspecified
    )


# AdGuard Home 0.107+ serialises the query log in lowercase (client, time,
# question, answer, reason). Older builds used IP/T/Question/Answer/Result, so
# every accessor accepts both spellings.
def entry_client(entry: dict) -> str:
    return str(entry.get("client") or entry.get("IP") or "").strip()


def entry_time(entry: dict) -> str:
    return str(entry.get("time") or entry.get("T") or "").strip()


def entry_question(entry: dict) -> dict:
    return entry.get("question") or entry.get("Question") or {}


def entry_answers(entry: dict) -> list[dict]:
    return entry.get("answer") or entry.get("Answer") or []


def answer_type(answer: dict) -> str:
    return str(answer.get("type") or answer.get("Type") or "").upper()


def answer_value(answer: dict) -> str:
    return str(answer.get("value") or answer.get("Value") or "").strip()


def entry_filtered(entry: dict) -> bool:
    result = entry.get("result") or entry.get("Result") or {}
    if result.get("IsFiltered"):
        return True
    reason = str(entry.get("reason") or "").lower()
    if reason.startswith(("filtered", "blocked")):
        return True
    return str(entry.get("status") or "").upper() in {"REFUSED", "NOTIMP"}


def pick_destination(entry: dict) -> tuple[str, str]:
    """Return (ip, kind) where kind is external/internal/blocked/none."""
    ips = [answer_value(a) for a in entry_answers(entry) if answer_type(a) in {"A", "AAAA"}]
    if entry_filtered(entry):
        return (ips[0] if ips else ""), "blocked"
    for ip in ips:
        if ip in ("0.0.0.0", "::"):
            return ip, "blocked"
    for ip in ips:
        if is_public(ip):
            return ip, "external"
    if ips:
        return ips[0], "internal"
    return "", "none"


def entry_epoch(stamp: str) -> float:
    try:
        return dt.datetime.fromisoformat(stamp).timestamp()
    except (ValueError, TypeError):
        return 0.0


def sync_queries() -> int:
    payload = adguard_get(f"/control/querylog?limit={QUERYLOG_LIMIT}")
    entries = payload.get("data") or []
    # Everything already in AdGuard's log when this collector first ran cannot be
    # attributed reliably (IPs are recycled by DHCP), so history starts now.
    cutoff = meta_get("collect_since")
    if not cutoff:
        cutoff = f"{time.time():.3f}"
        meta_set("collect_since", cutoff)
    try:
        since_epoch = float(cutoff)
    except ValueError:
        since_epoch = 0.0
    inserted = 0
    with _LOCK:
        conn = db()
        identity = {
            row["ip"]: row
            for row in conn.execute("SELECT mac, ip, name, device_type FROM devices WHERE ip <> ''")
        }
        for entry in entries:
            domain = str(entry_question(entry).get("name") or "").strip().rstrip(".").lower()
            if not domain:
                continue
            client_ip = entry_client(entry)
            qtype = str(entry_question(entry).get("type") or entry_question(entry).get("Qtype") or "")
            ts = entry_time(entry)
            if entry_epoch(ts) < since_epoch:
                continue
            dest_ip, dest_kind = pick_destination(entry)
            digest = hashlib.sha1(
                f"{ts}|{client_ip}|{domain}|{qtype}|{dest_ip}".encode()
            ).hexdigest()
            device = identity.get(client_ip)
            cur = conn.execute(
                "INSERT OR IGNORE INTO queries"
                "(id, ts, client_ip, client_mac, client_name, client_type, domain, qtype,"
                " dest_ip, dest_kind, blocked, filtered)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (digest, ts, client_ip,
                 device["mac"] if device else None,
                 device["name"] if device else (client_ip or None),
                 device["device_type"] if device else None,
                 domain, qtype, dest_ip, dest_kind,
                 1 if dest_kind == "blocked" else 0,
                 1 if entry_filtered(entry) else 0),
            )
            inserted += cur.rowcount
        conn.commit()
    _LAST["queries"] = dt.datetime.now().isoformat(timespec="seconds")
    return inserted


# ------------------------------------------------------------------- inventory
LABEL_RE = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')


def parse_router_metrics(text: str) -> list[dict[str, str]]:
    devices: list[dict[str, str]] = []
    for line in text.splitlines():
        if not line.startswith("router_connected_device_info{"):
            continue
        body = line[len("router_connected_device_info{"):].rsplit("}", 1)[0]
        labels = {
            key: value.replace('\\"', '"').replace("\\n", "\n").replace("\\\\", "\\")
            for key, value in LABEL_RE.findall(body)
        }
        if labels.get("mac"):
            devices.append(labels)
    return devices


def sync_inventory() -> int:
    with urllib.request.urlopen(ROUTER_EXPORTER_URL, timeout=25) as response:
        text = response.read().decode("utf-8", "replace")
    devices = parse_router_metrics(text)
    if not devices:
        raise RuntimeError("router-exporter returned no device inventory")
    now = dt.datetime.now().isoformat(timespec="seconds")
    with _LOCK:
        conn = db()
        for device in devices:
            mac = device.get("mac", "").upper()
            info = classify.classify(mac, device.get("name", ""), _OUI, _OVERRIDES)
            conn.execute(
                "INSERT INTO devices(mac, ip, name, device_type, vendor, network, port, ssid, last_seen, source)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)"
                " ON CONFLICT(mac) DO UPDATE SET ip=excluded.ip, name=excluded.name,"
                " device_type=excluded.device_type, vendor=excluded.vendor,"
                " network=excluded.network, port=excluded.port, ssid=excluded.ssid,"
                " last_seen=excluded.last_seen, source=excluded.source",
                (mac, device.get("ip", ""), info["name"], info["device_type"],
                 info["vendor"], device.get("network", ""), device.get("port", ""),
                 device.get("ssid", ""), now, info["source"]),
            )
        conn.commit()
    _LAST["inventory"] = now
    return len(devices)


# -------------------------------------------------------------------- geo / home
def ip_api_batch(ips: list[str]) -> list[dict]:
    fields = "status,message,country,countryCode,city,lat,lon,org,isp,query"
    body = json.dumps(ips).encode()
    request = urllib.request.Request(
        f"http://ip-api.com/batch?fields={fields}", data=body,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def sync_geo() -> int:
    if GEOIP_API != "ip-api":
        return 0
    with _LOCK:
        rows = db().execute(
            "SELECT DISTINCT q.dest_ip FROM queries q LEFT JOIN geo g ON g.ip = q.dest_ip"
            " WHERE q.dest_kind = 'external' AND q.dest_ip <> ''"
            "   AND (g.ip IS NULL OR (g.ok = 0 AND g.ts < ?)) LIMIT 100",
            ((dt.datetime.now() - dt.timedelta(days=1)).isoformat(),),
        ).fetchall()
    pending = [row["dest_ip"] for row in rows if is_public(row["dest_ip"])]
    if not pending:
        return 0
    results = ip_api_batch(pending)
    now = dt.datetime.now().isoformat(timespec="seconds")
    with _LOCK:
        conn = db()
        for result in results:
            ip = result.get("query", "")
            ok = 1 if result.get("status") == "success" else 0
            conn.execute(
                "INSERT INTO geo(ip, ok, country, city, lat, lon, org, ts) VALUES(?,?,?,?,?,?,?,?)"
                " ON CONFLICT(ip) DO UPDATE SET ok=excluded.ok, country=excluded.country,"
                " city=excluded.city, lat=excluded.lat, lon=excluded.lon,"
                " org=excluded.org, ts=excluded.ts",
                (ip, ok, result.get("country", ""), result.get("city", ""),
                 result.get("lat"), result.get("lon"),
                 result.get("org") or result.get("isp") or "", now),
            )
        conn.commit()
    _LAST["geo"] = now
    return len(results)


def home_location() -> dict:
    if HOME_FILE.exists():
        try:
            return json.loads(HOME_FILE.read_text(encoding="utf-8"))
        except ValueError:
            pass
    cached = meta_get("home")
    if cached:
        try:
            return json.loads(cached)
        except ValueError:
            pass
    if GEOIP_API != "ip-api":
        return {}
    try:
        with urllib.request.urlopen("https://api.ipify.org?format=json", timeout=15) as res:
            public_ip = json.loads(res.read().decode())["ip"]
        with urllib.request.urlopen(
            f"http://ip-api.com/json/{public_ip}?fields=status,country,city,lat,lon,isp,query",
            timeout=15,
        ) as res:
            data = json.loads(res.read().decode())
        if data.get("status") == "success":
            home = {"lat": data["lat"], "lon": data["lon"], "city": data.get("city", ""),
                    "country": data.get("country", ""), "isp": data.get("isp", ""),
                    "public_ip": data.get("query", public_ip), "source": "ip-geolocation"}
            meta_set("home", json.dumps(home))
            return home
    except Exception:
        pass
    return {}


# ------------------------------------------------------------------------ API
def query_rows(sql: str, params: tuple = ()) -> list[dict]:
    with _LOCK:
        return [dict(row) for row in db().execute(sql, params).fetchall()]


def api_devices() -> dict:
    rows = query_rows(
        "SELECT d.mac, d.ip, d.name, d.device_type, d.vendor, d.network, d.port, d.ssid,"
        "       d.last_seen, COUNT(q.id) AS queries, MAX(q.ts) AS last_query"
        " FROM devices d LEFT JOIN queries q ON q.client_mac = d.mac"
        " GROUP BY d.mac ORDER BY queries DESC, d.name"
    )
    for row in rows:
        row["icon"] = classify.TYPE_ICONS.get(row["device_type"], "❔")
    return {"devices": rows, "count": len(rows)}


def api_map(device_mac: str = "", hours: int = 168) -> dict:
    since = (dt.datetime.now() - dt.timedelta(hours=hours)).isoformat()
    where = "q.dest_kind = 'external' AND q.ts >= ? AND g.ok = 1"
    params: list = [since]
    if device_mac:
        where += " AND q.client_mac = ?"
        params.append(device_mac)
    rows = query_rows(
        "SELECT g.lat, g.lon, g.country, g.city, g.org, COUNT(*) AS hits,"
        "       COUNT(DISTINCT q.domain) AS domains, COUNT(DISTINCT q.client_mac) AS clients"
        f" FROM queries q JOIN geo g ON g.ip = q.dest_ip WHERE {where}"
        " GROUP BY ROUND(g.lat, 1), ROUND(g.lon, 1) ORDER BY hits DESC LIMIT 400",
        tuple(params),
    )
    top = query_rows(
        "SELECT g.lat, g.lon, q.domain, COUNT(*) AS hits"
        f" FROM queries q JOIN geo g ON g.ip = q.dest_ip WHERE {where}"
        " GROUP BY ROUND(g.lat, 1), ROUND(g.lon, 1), q.domain"
        " ORDER BY hits DESC LIMIT 400",
        tuple(params),
    )
    by_point: dict[tuple, list] = {}
    for row in top:
        by_point.setdefault((round(row["lat"], 1), round(row["lon"], 1)), []).append(row)
    for row in rows:
        names = by_point.get((round(row["lat"], 1), round(row["lon"], 1)), [])[:6]
        row["top_domains"] = [{"domain": n["domain"], "hits": n["hits"]} for n in names]
    stats = query_rows(
        "SELECT dest_kind, COUNT(*) AS n FROM queries WHERE ts >= ? GROUP BY dest_kind", (since,)
    )
    return {"home": home_location(), "points": rows, "stats": stats,
            "window_hours": hours, "last": _LAST}


def api_internal(hours: int = 168) -> dict:
    since = (dt.datetime.now() - dt.timedelta(hours=hours)).isoformat()
    rows = query_rows(
        "SELECT q.dest_ip, COUNT(*) AS hits, COUNT(DISTINCT COALESCE(q.client_mac, q.client_ip)) AS clients"
        " FROM queries q WHERE q.dest_kind = 'internal' AND q.ts >= ?"
        " GROUP BY q.dest_ip ORDER BY hits DESC LIMIT 50", (since,)
    )
    devices = {d["ip"]: d for d in api_devices()["devices"]}
    for row in rows:
        target = devices.get(row["dest_ip"])
        row["target_name"] = target["name"] if target else row["dest_ip"]
        row["target_type"] = target["device_type"] if target else "desconocido"
        row["icon"] = classify.TYPE_ICONS.get(row["target_type"], "❔")
        row["sources"] = query_rows(
            "SELECT COALESCE(client_name, client_ip) AS name, COUNT(*) AS hits FROM queries"
            " WHERE dest_kind='internal' AND dest_ip=? AND ts>=?"
            " GROUP BY COALESCE(client_mac, client_ip) ORDER BY hits DESC LIMIT 10",
            (row["dest_ip"], since),
        )
    return {"internal": rows}


def api_recent(limit: int = 200) -> dict:
    rows = query_rows(
        "SELECT q.ts, q.client_ip, q.domain, q.qtype, q.dest_ip, q.dest_kind, q.blocked,"
        "       g.city, g.country,"
        "       COALESCE(q.client_name, q.client_ip) AS name, q.client_type AS device_type"
        " FROM queries q LEFT JOIN geo g ON g.ip = q.dest_ip"
        " ORDER BY q.ts DESC LIMIT ?", (limit,)
    )
    return {"queries": rows}


def api_summary() -> dict:
    counts = {row["dest_kind"]: row["n"] for row in query_rows(
        "SELECT dest_kind, COUNT(*) AS n FROM queries GROUP BY dest_kind")}
    total = query_rows("SELECT COUNT(*) AS n, COUNT(DISTINCT domain) AS domains FROM queries")[0]
    top_domains = query_rows(
        "SELECT domain, COUNT(*) AS hits FROM queries GROUP BY domain ORDER BY hits DESC LIMIT 15")
    top_countries = query_rows(
        "SELECT g.country, COUNT(*) AS hits FROM queries q JOIN geo g ON g.ip=q.dest_ip"
        " WHERE q.dest_kind='external' AND g.ok=1 GROUP BY g.country ORDER BY hits DESC LIMIT 10")
    return {"total_queries": total["n"], "domains": total["domains"], "kinds": counts,
            "top_domains": top_domains, "top_countries": top_countries,
            "devices": api_devices()["count"], "home": home_location(),
            "last": _LAST, "adguard": ADGUARD_URL}


def api_privacy(hours: int = 168, limit: int = 40) -> dict:
    """Per-device external destinations, flagging tracker domains and silent devices."""
    since = (dt.datetime.now() - dt.timedelta(hours=hours)).isoformat()
    rows = query_rows(
        "SELECT d.mac, d.ip, d.name, d.device_type, d.network, d.ssid, d.port,"
        "       COUNT(q.id) AS hits,"
        "       SUM(CASE WHEN q.dest_kind='external' THEN 1 ELSE 0 END) AS external,"
        "       SUM(CASE WHEN q.blocked=1 THEN 1 ELSE 0 END) AS blocked"
        " FROM devices d LEFT JOIN queries q ON q.client_mac = d.mac AND q.ts >= ?"
        " GROUP BY d.mac ORDER BY hits DESC, d.name", (since,)
    )
    devices = []
    for row in rows:
        domains = query_rows(
            "SELECT domain, dest_kind, COUNT(*) AS hits, MAX(blocked) AS blocked"
            " FROM queries WHERE client_mac = ? AND ts >= ? AND dest_kind IN ('external','blocked')"
            " GROUP BY domain ORDER BY hits DESC LIMIT ?", (row["mac"], since, limit)
        )
        for domain in domains:
            domain["tracker"] = is_tracker(domain["domain"])
        tracker_hits = sum(d["hits"] for d in domains if d["tracker"])
        row["domains"] = domains
        row["tracker_hits"] = tracker_hits
        row["silent"] = row["hits"] == 0
        row["icon"] = classify.TYPE_ICONS.get(row["device_type"], "❔")
        devices.append(row)
    destinations = query_rows(
        "SELECT g.lat, g.lon, g.country, g.city, COUNT(*) AS hits"
        " FROM queries q JOIN geo g ON g.ip = q.dest_ip"
        " WHERE q.dest_kind='external' AND q.ts >= ? AND g.ok=1"
        " GROUP BY ROUND(g.lat,1), ROUND(g.lon,1) ORDER BY hits DESC LIMIT 200", (since,)
    )
    return {"devices": devices, "destinations": destinations,
            "trackers": sorted({d["domain"] for dev in devices for d in dev["domains"] if d["tracker"]}),
            "window_hours": hours}


# Domains and substrings that are almost always telemetry, analytics or ad
# delivery. Local list: no external lookup, easy to extend.
TRACKER_DOMAINS = (
    "doubleclick.net", "google-analytics.com", "googletagmanager.com",
    "googlesyndication.com", "googleadservices.com", "adservice.google.com",
    "app-measurement.com", "firebase-settings.crashlytics.com",
    "crashlytics.com", "facebook.com", "graph.facebook.com", "connect.facebook.net",
    "appsflyer.com", "adjust.com", "branch.io", "kochava.com", "singular.net",
    "mixpanel.com", "segment.io", "segment.com", "amplitude.com", "heap.io",
    "sentry.io", "bugsnag.com", "newrelic.com", "datadoghq.com", "loggly.com",
    "hotjar.com", "criteo.com", "criteo.net", "taboola.com", "outbrain.com",
    "adsrvr.org", "scorecardresearch.com", "quantserve.com", "quantcount.com",
    "rubiconproject.com", "pubmatic.com", "openx.net", "smartadserver.com",
    "adnxs.com", "casalemedia.com", "moatads.com", "imrworldwide.com",
    "teads.tv", "inmobi.com", "unityads.unity3d.com", "applovin.com",
    "vungle.com", "ironsrc.com", "flurry.com", "umeng.com", "yandex.ru",
    "samsungads.com", "samsungacr.com", "samsungcloudsolution.com",
    "lgsmartad.com", "lgappstv.com", "xstu.tv", "hisense.com",
    "telemetry.mozilla.org", "incoming.telemetry.mozilla.org",
    "watson.telemetry.microsoft.com", "v10.events.data.microsoft.com",
    "settings-win.data.microsoft.com", "vortex.data.microsoft.com",
    "device-metrics-us.amazon.com", "amazon-adsystem.com",
)
TRACKER_TOKENS = ("telemetry", "analytics", "tracking", "metrics", "beacon",
                  "collect", "stats.", "ads.", "adserver", "pixel")


def is_tracker(domain: str) -> bool:
    lowered = (domain or "").lower()
    if any(lowered == d or lowered.endswith("." + d) for d in TRACKER_DOMAINS):
        return True
    return any(token in lowered for token in TRACKER_TOKENS)


def render_metrics() -> str:
    """Prometheus exposition for Grafana: per-device DNS activity and destinations."""
    since_24h = (dt.datetime.now() - dt.timedelta(hours=24)).isoformat()
    lines = [
        "# HELP netviz_queries_total DNS queries recorded per kind.",
        "# TYPE netviz_queries_total counter",
    ]
    for row in query_rows("SELECT dest_kind, COUNT(*) AS n FROM queries GROUP BY dest_kind"):
        lines.append(f'netviz_queries_total{{kind="{prom_label(str(row["dest_kind"] or "none"))}"}} {row["n"]}')

    lines += [
        "# HELP netviz_devices Connected devices reported by the router.",
        "# TYPE netviz_devices gauge",
    ]
    for row in query_rows("SELECT network, COUNT(*) AS n FROM devices GROUP BY network"):
        lines.append(f'netviz_devices{{network="{prom_label(str(row["network"] or ""))}"}} {row["n"]}')

    lines += [
        "# HELP netviz_device_queries_total DNS queries attributed to one device (24 h).",
        "# TYPE netviz_device_queries_total counter",
        "# HELP netviz_device_blocked_total Queries blocked by AdGuard for one device (24 h).",
        "# TYPE netviz_device_blocked_total counter",
        "# HELP netviz_device_tracker_total Queries to known telemetry/tracking domains (24 h).",
        "# TYPE netviz_device_tracker_total counter",
        "# HELP netviz_device_silent 1 when the device sent no DNS query in the window.",
        "# TYPE netviz_device_silent gauge",
    ]
    rows = query_rows(
        "SELECT d.mac, d.ip, d.name, d.device_type, d.network,"
        "       COUNT(q.id) AS hits,"
        "       COALESCE(SUM(CASE WHEN q.blocked=1 THEN 1 ELSE 0 END), 0) AS blocked"
        " FROM devices d LEFT JOIN queries q ON q.client_mac = d.mac AND q.ts >= ?"
        " GROUP BY d.mac ORDER BY hits DESC", (since_24h,)
    )
    tracker_by_device: dict[str, int] = {}
    for row in query_rows(
        "SELECT client_mac, domain, COUNT(*) AS hits FROM queries"
        " WHERE ts >= ? AND dest_kind IN ('external','blocked') GROUP BY client_mac, domain",
        (since_24h,),
    ):
        if is_tracker(row["domain"]):
            key = row["client_mac"] or ""
            tracker_by_device[key] = tracker_by_device.get(key, 0) + row["hits"]

    for row in rows:
        labels = (
            f'device="{prom_label(row["name"] or row["mac"])}",'
            f'type="{prom_label(row["device_type"] or "desconocido")}",'
            f'network="{prom_label(row["network"] or "")}",ip="{prom_label(row["ip"] or "")}"'
        )
        lines.append(f"netviz_device_queries_total{{{labels}}} {row['hits']}")
        lines.append(f"netviz_device_blocked_total{{{labels}}} {row['blocked']}")
        lines.append(f"netviz_device_tracker_total{{{labels}}} {tracker_by_device.get(row['mac'], 0)}")
        lines.append(f"netviz_device_silent{{{labels}}} {1 if row['hits'] == 0 else 0}")

    lines += [
        "# HELP netviz_domain_queries_total Top domains per device (bounded to 500 series).",
        "# TYPE netviz_domain_queries_total counter",
    ]
    domains = query_rows(
        "SELECT COALESCE(d.name, q.client_name, 'IP ' || q.client_ip) AS device,"
        "       q.domain, q.dest_kind, MAX(q.blocked) AS blocked, COUNT(*) AS hits"
        " FROM queries q LEFT JOIN devices d ON d.mac = q.client_mac"
        " WHERE q.ts >= ? GROUP BY COALESCE(q.client_mac, q.client_ip), q.domain"
        " ORDER BY hits DESC LIMIT 500", (since_24h,)
    )
    for row in domains:
        tracker = 1 if is_tracker(row["domain"]) else 0
        labels = (
            f'device="{prom_label(row["device"] or "sin identificar")}",'
            f'domain="{prom_label(row["domain"])}",'
            f'kind="{prom_label(str(row["dest_kind"] or "none"))}",tracker="{tracker}"'
        )
        lines.append(f"netviz_domain_queries_total{{{labels}}} {row['hits']}")

    lines += [
        "# HELP netviz_destination_total DNS destinations aggregated by approximate location.",
        "# TYPE netviz_destination_total counter",
    ]
    for row in query_rows(
        "SELECT g.lat, g.lon, g.country, g.city, COUNT(*) AS hits"
        " FROM queries q JOIN geo g ON g.ip = q.dest_ip"
        " WHERE q.dest_kind='external' AND g.ok=1"
        " GROUP BY ROUND(g.lat,1), ROUND(g.lon,1) ORDER BY hits DESC LIMIT 200"
    ):
        labels = (
            f'lat="{row["lat"]}",lon="{row["lon"]}",'
            f'city="{prom_label(row["city"] or "")}",country="{prom_label(row["country"] or "")}"'
        )
        lines.append(f"netviz_destination_total{{{labels}}} {row['hits']}")

    lines += [
        "# HELP netviz_last_collect_timestamp_seconds Unix time of the last successful collection step.",
        "# TYPE netviz_last_collect_timestamp_seconds gauge",
    ]
    for step, stamp in _LAST.items():
        try:
            parsed = dt.datetime.fromisoformat(stamp).timestamp()
        except ValueError:
            continue
        lines.append(f'netviz_last_collect_timestamp_seconds{{step="{step}"}} {parsed:.0f}')
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------- server
class Handler(BaseHTTPRequestHandler):
    server_version = "netviz/1.0"

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        path = parsed.path
        try:
            if path in ("/", "/index.html"):
                body = (STATIC_DIR / "index.html").read_bytes()
                return self._send(200, body, "text/html; charset=utf-8")
            if path == "/healthz":
                return self._send(200, b"ok\n", "text/plain; charset=utf-8")
            if path == "/api/summary":
                return self._json(api_summary())
            if path == "/api/map":
                device = (params.get("device") or [""])[0]
                hours = int((params.get("hours") or ["168"])[0])
                return self._json(api_map(device, hours))
            if path == "/api/devices":
                return self._json(api_devices())
            if path == "/api/internal":
                return self._json(api_internal())
            if path == "/api/recent":
                limit = int((params.get("limit") or ["200"])[0])
                return self._json(api_recent(limit))
            if path == "/api/privacy":
                hours = int((params.get("hours") or ["168"])[0])
                return self._json(api_privacy(hours))
            if path == "/metrics":
                return self._send(200, render_metrics().encode("utf-8"),
                                  "text/plain; version=0.0.4; charset=utf-8")
            return self._send(404, b"not found\n", "text/plain; charset=utf-8")
        except Exception as exc:  # noqa: BLE001 - report without leaking internals
            return self._json({"error": type(exc).__name__}, status=500)

    def _json(self, payload: dict, status: int = 200) -> None:
        self._send(status, json.dumps(payload).encode("utf-8"), "application/json")

    def log_message(self, format: str, *args) -> None:  # noqa: A002 - base class signature
        return


def poll_loop() -> None:
    while True:
        for name, step in (("inventory", sync_inventory), ("queries", sync_queries), ("geo", sync_geo)):
            try:
                count = step()
                print(f"[{dt.datetime.now():%H:%M:%S}] {name}: {count}", flush=True)
            except Exception as exc:  # noqa: BLE001
                print(f"[{dt.datetime.now():%H:%M:%S}] {name} failed: {type(exc).__name__}: {exc}",
                      flush=True)
        time.sleep(POLL_SECONDS)


def main() -> None:
    db()
    if classify.download_oui(OUI_PATH):
        print(f"oui database ready ({OUI_PATH})", flush=True)
    else:
        print("oui download unavailable; using built-in vendor table", flush=True)
    refresh_static_data()
    home_location()
    for step in (sync_inventory, sync_queries, sync_geo):
        try:
            step()
        except Exception as exc:  # noqa: BLE001
            print(f"initial {step.__name__} failed: {type(exc).__name__}: {exc}", flush=True)
    threading.Thread(target=poll_loop, daemon=True).start()
    print(f"netviz listening on :{HTTP_PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
