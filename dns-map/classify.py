#!/usr/bin/env python3
"""Device naming and type inference for a home LAN.

Sources, in priority order:
  1. device-overrides.csv (local, git-ignored, keyed by MAC)
  2. hostname heuristics
  3. MAC OUI vendor heuristics (with an optional downloaded IEEE oui.csv)
  4. honest fallback: "desconocido"
"""

from __future__ import annotations

import csv
import os
import re
import urllib.request
from pathlib import Path

OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"

# Small built-in subset so classification works before/without the IEEE file.
FALLBACK_VENDORS: dict[str, str] = {
    "001D94": "ZTE", "3C7895": "ZTE", "581122": "ZTE",
    "249E7D": "Roborock", "10B676": "HP", "DE4373": "Xiaomi",
    "8C3F44": "Espressif", "803E4F": "Espressif",
    "A4C138": "Apple", "F0766F": "Apple", "D0817A": "Apple",
    "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi",
    "18B430": "Nest", "44650D": "Amazon", "747548": "Amazon",
    "F4F5D8": "Google", "3C5AB4": "Google", "B0FC36": "Sonos",
    "001788": "Signify (Philips Hue)", "ECB5FA": "Signify (Philips Hue)",
    "84FD27": "Silicon Labs (IKEA/Smart)", "680AE2": "IKEA",
    "5CAAFD": "Sonoff (ITEAD)", "84F3EB": "Espressif",
    "8CF681": "Tuya", "D8F15B": "Espressif",
}

# Vendor fragment -> (type, note). First match wins.
VENDOR_TYPES: list[tuple[str, str]] = [
    ("roborock", "aspirador"),
    ("signify", "domótica"),
    ("philips hue", "domótica"),
    ("ikea", "domótica"),
    ("sonoff", "domótica"),
    ("itead", "domótica"),
    ("tuya", "domótica"),
    ("espressif", "domótica"),
    ("silicon labs", "domótica"),
    ("shelly", "domótica"),
    ("sonos", "altavoz"),
    ("nest", "cámara"),
    ("ring", "cámara"),
    ("hikvision", "cámara"),
    ("dahua", "cámara"),
    ("ezviz", "cámara"),
    ("raspberry", "ordenador"),
    ("climax", "alarma"),
    ("ajax systems", "alarma"),
    ("synology", "NAS"),
    ("qnap", "NAS"),
    ("brother", "impresora"),
    ("epson", "impresora"),
    ("canon", "impresora"),
    ("hewlett", "impresora"),
    ("ubiquiti", "red"),
    ("asustek", "ordenador"),
    ("asustek computer", "ordenador"),
    ("tp-link", "red"),
    ("netgear", "red"),
    ("d-link", "red"),
    ("zte", "red"),
    ("huawei", "red"),
    ("amazon", "altavoz/TV"),
    ("google", "TV/altavoz"),
    ("sony", "televisión"),
    ("lg electronics", "televisión"),
    ("samsung", "móvil/TV"),
    ("apple", "Apple"),
    ("xiaomi", "Xiaomi"),
]

# Hostname fragment -> type. Checked before the vendor table.
HOSTNAME_TYPES: list[tuple[str, str]] = [
    ("roborock", "aspirador"), ("vacuum", "aspirador"), ("aspirador", "aspirador"),
    ("bravia", "televisión"), ("aquos", "televisión"), ("chromecast", "televisión"),
    ("appletv", "televisión"), ("firetv", "televisión"), ("roku", "televisión"),
    ("androidtv", "televisión"), ("smart-tv", "televisión"), ("-tv", "televisión"),
    ("printer", "impresora"), ("epson", "impresora"), ("brother", "impresora"),
    ("iphone", "móvil"), ("poco", "móvil"), ("redmi", "móvil"),
    ("galaxy", "móvil"), ("pixel", "móvil"), ("oneplus", "móvil"),
    ("ipad", "tablet"), ("tab-", "tablet"), ("tablet", "tablet"),
    ("macbook", "ordenador"), ("laptop", "ordenador"), ("thinkpad", "ordenador"),
    ("desktop", "ordenador"), ("imac", "ordenador"), ("mac-mini", "ordenador"),
    ("camera", "cámara"), ("ipcam", "cámara"), ("doorbell", "cámara"), ("tapo", "cámara"),
    ("echo", "altavoz"), ("alexa", "altavoz"), ("homepod", "altavoz"), ("sonos", "altavoz"),
    ("plug", "domótica"), ("bulb", "domótica"), ("lamp", "domótica"), ("luz", "domótica"),
    ("light", "domótica"), ("hue", "domótica"), ("tradfri", "domótica"),
    ("shelly", "domótica"), ("sonoff", "domótica"), ("tuya", "domótica"),
    ("switch", "red"), ("router", "red"), ("unifi", "red"),
    ("nas", "NAS"), ("diskstation", "NAS"),
    ("net_ac", "domótica"), ("net_cd", "domótica"), ("net_dc", "domótica"),
    ("dishwasher", "electrodoméstico"), ("lavavajillas", "electrodoméstico"),
    ("washing", "electrodoméstico"), ("washer", "electrodoméstico"),
    ("fridge", "electrodoméstico"), ("oven", "electrodoméstico"),
    ("officejet", "impresora"), ("deskjet", "impresora"), ("envy", "impresora"),
]

# Patterns that a plain substring table cannot express.
HOSTNAME_PATTERNS: list[tuple[str, str]] = [
    (r"^hp[0-9a-f]{6}$", "impresora"),      # HP printers default to HP<MAC>
    (r"^mac(-|$|book|mini)", "ordenador"),  # "Mac", "MacBookPro", "Mac-mini"
]

TYPE_ICONS = {
    "móvil": "📱", "tablet": "📱", "ordenador": "💻", "televisión": "📺",
    "aspirador": "🧹", "impresora": "🖨️", "cámara": "📷", "altavoz": "🔊",
    "domótica": "💡", "red": "🌐", "NAS": "🗄️", "Apple": "🍎",
    "electrodoméstico": "🧺", "alarma": "🚨",
    "Xiaomi": "📱", "móvil/TV": "📱", "TV/altavoz": "📺", "altavoz/TV": "🔊",
    "desconocido": "❔",
}


def load_overrides(path: Path) -> dict[str, dict[str, str]]:
    try:
        with path.open(encoding="utf-8", newline="") as handle:
            return {
                (row.get("mac") or "").strip().upper().replace("-", ":"): row
                for row in csv.DictReader(handle)
                if (row.get("mac") or "").strip()
            }
    except OSError:
        return {}


def load_oui(path: Path) -> dict[str, str]:
    """Parse an IEEE oui.csv into {6 hex chars: organization}."""
    table: dict[str, str] = {}
    try:
        with path.open(encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                assignment = (row.get("Assignment") or "").strip().upper()
                org = (row.get("Organization Name") or "").strip()
                if len(assignment) == 6 and org:
                    table[assignment] = org
    except (OSError, csv.Error):
        return {}
    return table


def download_oui(path: Path, timeout: int = 60) -> bool:
    if path.exists() and path.stat().st_size > 100_000:
        return True
    request = urllib.request.Request(
        OUI_URL, headers={"User-Agent": "netviz/1.0 (home LAN inventory)"}
    )
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = response.read()
        if len(data) < 100_000:
            return False
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, path)
        return True
    except Exception as exc:  # noqa: BLE001 - report, then use the built-in table
        print(f"oui download failed: {type(exc).__name__}: {exc}", flush=True)
        return False


def short_vendor(vendor: str) -> str:
    """Trim an OUI organisation to a readable brand: 'ASUSTek COMPUTER INC.' -> 'ASUSTek'."""
    cleaned = re.sub(
        r"\b(inc|incorporated|ltd|llc|co|corp|corporation|company|gmbh|s\.?a\.?u?|b\.?v\.?|ag|kg)\b\.?",
        " ", vendor or "", flags=re.I,
    )
    parts = [part.strip(",.") for part in re.split(r"[\s,]+", cleaned) if part.strip(",.")]
    return (parts[0] if parts else (vendor or "")).strip()[:24]


def vendor_for(mac: str, oui: dict[str, str]) -> str:
    key = mac.upper().replace("-", ":").replace(":", "")[:6]
    return oui.get(key) or FALLBACK_VENDORS.get(key, "")


def _match(hostname: str) -> str | None:
    lowered = hostname.lower()
    for fragment, device_type in HOSTNAME_TYPES:
        if fragment in lowered:
            return device_type
    for pattern, device_type in HOSTNAME_PATTERNS:
        if re.match(pattern, lowered):
            return device_type
    return None


def _vendor_type(vendor: str) -> str | None:
    lowered = vendor.lower()
    for fragment, device_type in VENDOR_TYPES:
        if fragment in lowered:
            return device_type
    return None


def classify(
    mac: str,
    hostname: str,
    oui: dict[str, str],
    overrides: dict[str, dict[str, str]],
) -> dict[str, str]:
    """Return {name, device_type, vendor, source} for one device."""
    vendor = vendor_for(mac, oui)
    hostname = (hostname or "").strip()
    override = overrides.get(mac.upper().replace("-", ":"), {})
    name = (override.get("name") or "").strip() or hostname
    device_type = (override.get("device_type") or "").strip()
    source = "override" if device_type else ""

    if not device_type:
        from_hostname = _match(hostname)
        if from_hostname:
            device_type, source = from_hostname, "hostname"
        else:
            from_vendor = _vendor_type(vendor)
            device_type = from_vendor or "desconocido"
            source = "vendor" if from_vendor else "unknown"

    if not name or name.lower() == "unknown":
        name = short_vendor(vendor) or mac.upper()

    return {"name": name, "device_type": device_type, "vendor": vendor, "source": source}
