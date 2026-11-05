#!/usr/bin/env python3
"""Genera capture/devices.json: ip -> {name, type} para etiquetar los flujos del sensor.

Cruza tres fuentes:
  1. dns-map (/api/devices): nombre y tipología inferida (override, hostname, OUI).
  2. Prometheus (router_connected_device_info): todos los equipos que ve el router.
  3. device-overrides.csv: correcciones manuales por MAC.

Uso:
    python3 scripts/build-device-names.py            # escribe capture/devices.json
    python3 scripts/build-device-names.py --check    # sólo muestra el resultado
"""

from __future__ import annotations

import argparse
import csv
import json
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "capture" / "devices.json"
OVERRIDES = ROOT / "device-overrides.csv"
DNS_MAP = "http://127.0.0.1:8080/api/devices"
PROM = "http://127.0.0.1:9090/api/v1/query?query=router_connected_device_info"


def get_json(url: str, timeout: int = 10) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def load_overrides() -> dict[str, str]:
    """MAC (mayúsculas) -> tipo."""
    if not OVERRIDES.exists():
        return {}
    out = {}
    with OVERRIDES.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            mac = (row.get("mac") or "").strip().upper()
            dtype = (row.get("device_type") or "").strip()
            if mac and dtype:
                out[mac] = dtype
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="no escribe el fichero")
    parser.add_argument("--out", default=str(OUT))
    args = parser.parse_args()

    overrides = load_overrides()
    devices: dict[str, dict] = {}

    # 1) router: todos los equipos conocidos (ip, mac, nombre)
    try:
        data = get_json(PROM)
        for serie in data.get("data", {}).get("result", []):
            m = serie.get("metric", {})
            ip, mac = m.get("ip"), (m.get("mac") or "").upper()
            if not ip:
                continue
            devices[ip] = {
                "name": m.get("name") or "",
                "type": overrides.get(mac, m.get("device_type") or "desconocido"),
                "mac": mac,
            }
    except Exception as exc:  # noqa: BLE001
        print(f"aviso: sin datos del router ({exc})")

    # 2) dns-map: tipología inferida (prioridad sobre el router si no es 'desconocido')
    try:
        data = get_json(DNS_MAP)
        for d in data.get("devices", []):
            ip = d.get("ip")
            if not ip:
                continue
            entry = devices.setdefault(ip, {"name": "", "type": "desconocido", "mac": ""})
            if d.get("name") and not entry.get("name"):
                entry["name"] = d["name"]
            dtype = d.get("device_type") or "desconocido"
            if dtype != "desconocido":
                entry["type"] = dtype
            if d.get("icon"):
                entry["icon"] = d["icon"]
    except Exception as exc:  # noqa: BLE001
        print(f"aviso: sin datos de dns-map ({exc})")

    # 3) overrides por MAC mandan
    for ip, entry in devices.items():
        mac = (entry.get("mac") or "").upper()
        if mac in overrides:
            entry["type"] = overrides[mac]

    devices = {ip: e for ip, e in sorted(devices.items()) if ip.startswith("192.168.")}

    print(f"{len(devices)} equipos")
    for ip, e in devices.items():
        print(f"  {ip:15} {e.get('type',''):15} {e.get('name','')}")

    if not args.check:
        Path(args.out).write_text(json.dumps(devices, indent=2, ensure_ascii=False) + "\n",
                                  encoding="utf-8")
        print(f"escrito {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
