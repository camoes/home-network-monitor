#!/usr/bin/env python3
"""Packet-capture flow sensor for macOS -> Prometheus.

Captures with tshark on one interface (BPF access via the `access_bpf` group, so
no root needed), extracts DNS names, TLS SNI and HTTP Host from the packets, and
exposes aggregated counters on 127.0.0.1:9101/metrics.

Los flujos sin SNI/Host/DNS (QUIC, conexiones ya establecidas) se pueden nombrar
con una tabla IP->etiqueta opcional (`cdn-map.json`, `--cdn`); el dominio
observado siempre manda y sin tabla el comportamiento es el de siempre.

Scope, stated honestly: a passive capture on one host only sees traffic that
this host sends or receives. It does NOT see other LAN devices unless the switch
or router mirrors their traffic to this interface.

Usage:
    python3 sensor.py --iface en0                 # live capture
    python3 sensor.py --replay capture.txt        # parse a saved tshark dump
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import ipaddress
import json
import os
import socket
import shutil
import subprocess
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

LISTEN_PORT = int(os.getenv("NETVIZ_CAPTURE_PORT", "9101"))
BIND_ADDR = os.getenv("NETVIZ_BIND", "127.0.0.1")
STATE_DIR = Path(os.getenv("NETVIZ_CAPTURE_STATE", str(Path.home() / ".netviz-capture")))
GEO_CACHE = STATE_DIR / "geo.json"
# Mapa IP->dominio aprendido del tráfico: si sólo vive en memoria, cada reinicio
# deja los flujos de vuelta en domain="" hasta el siguiente ClientHello.
PEERS_CACHE = STATE_DIR / "peers.json"
PEERS_TTL = float(os.getenv("NETVIZ_PEERS_TTL_H", "36")) * 3600   # caducidad (24-48 h)
TSHARK = (os.getenv("NETVIZ_TSHARK")
          or shutil.which("tshark")
          or "/opt/homebrew/bin/tshark")
BPF_FILTER = os.getenv("NETVIZ_BPF", "udp port 53 or tcp port 443 or udp port 443 or tcp port 80")
MAX_FLOWS = 4000
MAX_DOMAINS = 3000
MAX_PEERS = 5000        # tope del mapa IP->dominio que se persiste

FIELDS = [
    "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "frame.len",
    "dns.qry.name", "tls.handshake.extensions_server_name", "http.host",
    # Número de protocolo IP: distingue tcp/udp y permite sostener «QUIC».
    "ip.proto", "ipv6.nxt",
]

SERVICE_PORTS = {"443": "https", "80": "http", "53": "dns"}
IP_PROTOS = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6"}

_LOCK = threading.RLock()
_FLOWS: dict[tuple[str, str, str, str], list[int]] = {}
_DOMAINS: dict[str, list[int]] = {}
_DSTS: dict[str, list[int]] = {}
_COUNTERS = {"packets": 0, "bytes": 0, "dns": 0, "sni": 0, "blocks": 0, "cdn": 0}
_LAST_PACKET = 0.0
_LOCAL_IPS: set[str] = set()
# En un puerto espejo ninguna IP del flujo es del propio PC: la dirección se
# decide por pertenencia a la LAN (src dentro = salida, dst dentro = entrada).
LAN_NETS: list = []   # varias redes: el router sirve 192.0.2.0/24 y 198.51.100.0/24
_PEER_DOMAIN: dict[str, str] = {}
# Cuándo se aprendió cada nombre (epoch): sin esto no hay caducidad y una IP de
# CDN reciclada seguiría etiquetada con el dominio del inquilino anterior.
_PEER_SEEN: dict[str, float] = {}
_PEERS_DIRTY = False   # hay cambios sin volcar a peers.json
# Cliente de la LAN -> tráfico hacia internet. Sin esto no se puede atribuir una
# salida a la tele, al lavavajillas o a un ordenador: sólo se vería el destino.
_CLIENTS: dict[tuple[str, str, str, str, str], list[int]] = {}
# ip -> {"name": ..., "type": ...} cargado de un JSON (--names)
_NAMES: dict[str, dict] = {}
MAX_CLIENTS = 4000
_GEO: dict[str, dict] = {}
_GEO_ATTEMPT: dict[str, float] = {}
_STATUS = {"tshark": "starting", "detail": ""}

# ---------------------------------------------- respaldo por IP (tabla de CDN)
# Un flujo QUIC/HTTP-3 o una conexión ya establecida llega sin SNI: el sensor no
# puede nombrarla. Esta tabla IP->etiqueta (JSON editable, sin tocar el pipeline)
# sólo rellena ese hueco; si el flujo trae dominio, el dominio manda.
CDN_DEBUG = os.getenv("NETVIZ_CDN_DEBUG", "").strip().lower() in ("1", "true", "yes", "on")
_CDN: list[tuple] = []        # [(ip_network, etiqueta)] por prefijo descendente
_CDN_ENABLED = False
_CDN_PATH: Path | None = None
_CDN_MTIME = 0.0
_CDN_SEEN: set[str] = set()   # destinos ya avisados por debug (una línea, no por paquete)
_CDN_BYTES: dict[str, list[int]] = {}


# ------------------------------------------------------------------ utilities
def local_ips(iface: str) -> set[str]:
    """Addresses that belong to this host right now (the LAN IP changes with DHCP)."""
    ips: set[str] = set()

    def add(value: str) -> None:
        value = (value or "").strip()
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return          # descarta basura: en Windows `ipconfig getifaddr` no existe
        ips.add(value)

    add("127.0.0.1")
    add("::1")
    try:
        out = subprocess.run(["ipconfig", "getifaddr", iface], capture_output=True,
                             text=True, timeout=5).stdout.strip()
        add(out)
    except Exception:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            add(str(info[4][0]))
    except Exception:
        pass
    return ips


def is_private(ip: str) -> bool:
    try:
        import ipaddress
        address = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (address.is_private or address.is_loopback or address.is_link_local
            or address.is_multicast or address.is_reserved or address.is_unspecified)


def load_geo() -> None:
    global _GEO
    try:
        _GEO = json.loads(GEO_CACHE.read_text())
    except (OSError, ValueError):
        _GEO = {}


def save_geo() -> None:
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        GEO_CACHE.write_text(json.dumps(_GEO))
    except OSError:
        pass


def geolocate(ips: list[str]) -> int:
    """Resolve approximate locations with ip-api (batched, cached)."""
    pending = [ip for ip in ips if ip not in _GEO and time.time() - _GEO_ATTEMPT.get(ip, 0) > 3600]
    pending = [ip for ip in pending if not is_private(ip)][:100]
    if not pending:
        return 0
    for ip in pending:
        _GEO_ATTEMPT[ip] = time.time()
    try:
        body = json.dumps(pending).encode()
        request = urllib.request.Request(
            "http://ip-api.com/batch?fields=status,country,city,lat,lon,org,query",
            data=body, headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=25) as response:
            results = json.loads(response.read().decode())
        for item in results:
            ip = item.get("query", "")
            _GEO[ip] = {
                "lat": item.get("lat"), "lon": item.get("lon"),
                "city": item.get("city") or "", "country": item.get("country") or "",
                "org": item.get("org") or "",
            } if item.get("status") == "success" else {"lat": None, "lon": None}
        save_geo()
        return len(results)
    except Exception:
        return 0


# ------------------------------------------------- ip -> dominio (persistente)
def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def learn_peer(peer: str, domain: str, when: float | None = None) -> None:
    """Aprende IP->dominio a partir de un nombre observado en la conexión.

    Sólo SNI/Host: una consulta DNS nombra lo que se pregunta, **no** al servidor
    que responde, así que nunca se llama desde un paquete DNS.
    """
    global _PEERS_DIRTY
    if not peer or not domain:
        return
    now = time.time() if when is None else when
    with _LOCK:
        changed = _PEER_DOMAIN.get(peer) != domain
        fresh = now - _PEER_SEEN.get(peer, 0) > 60      # refresca la caducidad
        _PEER_DOMAIN[peer] = domain
        _PEER_SEEN[peer] = now
        if changed or fresh:
            _PEERS_DIRTY = True


def forget_peer(peer: str) -> bool:
    """Olvida una IP (p. ej. una entrada contaminada por el nombre de una consulta)."""
    global _PEERS_DIRTY
    with _LOCK:
        if _PEER_DOMAIN.pop(peer, None) is None:
            return False
        _PEER_SEEN.pop(peer, None)
        _PEERS_DIRTY = True
    return True


def prune_peers(now: float | None = None) -> int:
    """Descarta los nombres caducados: una IP de CDN reciclada no debe heredarlos."""
    global _PEERS_DIRTY
    now = time.time() if now is None else now
    with _LOCK:
        for peer in list(_PEER_DOMAIN):
            _PEER_SEEN.setdefault(peer, now)     # entradas sin fecha: cuentan desde ahora
        expired = [ip for ip, ts in _PEER_SEEN.items() if now - ts > PEERS_TTL]
        for ip in expired:
            _PEER_DOMAIN.pop(ip, None)
            _PEER_SEEN.pop(ip, None)
        if len(_PEER_DOMAIN) > MAX_PEERS:      # los más antiguos caen primero
            for ip, _ts in sorted(_PEER_SEEN.items(), key=lambda kv: kv[1])[:len(_PEER_DOMAIN) - MAX_PEERS]:
                _PEER_DOMAIN.pop(ip, None)
                _PEER_SEEN.pop(ip, None)
                expired.append(ip)
        if expired:
            _PEERS_DIRTY = True
    return len(expired)


def save_peers(force: bool = False) -> bool:
    """Vuelca el mapa IP->dominio a STATE_DIR/peers.json (escritura atómica)."""
    global _PEERS_DIRTY
    with _LOCK:
        if not (_PEERS_DIRTY or force):
            return False
        data = {"version": 1, "ttl_seconds": int(PEERS_TTL), "peers": {
            ip: {"domain": domain, "ts": _PEER_SEEN.get(ip, time.time())}
            for ip, domain in _PEER_DOMAIN.items()}}
        _PEERS_DIRTY = False
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        tmp = PEERS_CACHE.with_name(PEERS_CACHE.name + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        os.replace(tmp, PEERS_CACHE)      # nunca deja un JSON a medias
        return True
    except OSError as exc:
        with _LOCK:
            _PEERS_DIRTY = True
        _say(f"aviso: no pude guardar {PEERS_CACHE}: {exc}")
        return False


def load_peers(now: float | None = None) -> int:
    """Recupera el mapa del disco al arrancar y tira lo caducado."""
    global _PEER_DOMAIN, _PEER_SEEN, _PEERS_DIRTY
    now = time.time() if now is None else now
    try:
        data = json.loads(PEERS_CACHE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return 0
    except (OSError, ValueError) as exc:
        _say(f"aviso: {PEERS_CACHE} ilegible ({exc}); se arranca sin nombres")
        return 0
    peers = data.get("peers") if isinstance(data, dict) else None
    if peers is None and isinstance(data, dict):
        peers = data            # compatibilidad con un mapa plano {ip: dominio}
    if not isinstance(peers, dict):
        _say(f"aviso: {PEERS_CACHE} sin mapa de peers; se ignora")
        return 0
    kept: dict[str, tuple[str, float]] = {}
    expired = 0
    for peer, item in peers.items():
        domain = item.get("domain") if isinstance(item, dict) else item
        raw_ts = item.get("ts") if isinstance(item, dict) else now
        try:
            ts = float(raw_ts) if raw_ts is not None else now
        except (TypeError, ValueError):
            ts = now
        if not isinstance(domain, str) or not domain.strip() or not _valid_ip(str(peer)):
            continue
        if now - ts > PEERS_TTL:
            expired += 1
            continue
        kept[str(peer)] = (domain.strip(), ts)
    with _LOCK:
        _PEER_DOMAIN = {ip: domain for ip, (domain, _ts) in kept.items()}
        _PEER_SEEN = {ip: ts for ip, (_domain, ts) in kept.items()}
        _PEERS_DIRTY = False
    if kept or expired:
        _say(f"peers: {len(kept)} nombres IP->dominio recuperados de {PEERS_CACHE}"
             + (f" ({expired} caducados)" if expired else ""))
    return len(kept)


# -------------------------------------------------------------------- parsing
def parse_line(line: str) -> dict | None:
    """Parse one tshark -T fields line into a flow record."""
    parts = line.rstrip("\n").split("\t")
    if len(parts) < len(FIELDS):
        parts += [""] * (len(FIELDS) - len(parts))
    field = dict(zip(FIELDS, parts))
    try:
        epoch = float(field["frame.time_epoch"])
        size = int(field["frame.len"] or 0)
    except ValueError:
        return None
    src = field["ip.src"] or field["ipv6.src"]
    dst = field["ip.dst"] or field["ipv6.dst"]
    if not dst:
        return None
    sni = (field["tls.handshake.extensions_server_name"] or "").strip()
    dns_name = (field["dns.qry.name"] or "").strip()
    domain = (sni or field["http.host"] or dns_name or "").strip().rstrip(".").lower()
    proto_num = (field["ip.proto"] or field["ipv6.nxt"] or "").strip()
    transport = IP_PROTOS.get(proto_num) or (
        "tcp" if (field["tcp.srcport"] or field["tcp.dstport"])
        else "udp" if (field["udp.srcport"] or field["udp.dstport"]) else "")
    return {"ts": epoch, "src": src, "dst": dst,
            "sport": (field["tcp.srcport"] or field["udp.srcport"] or "").strip(),
            "dport": (field["tcp.dstport"] or field["udp.dstport"] or "").strip(),
            "bytes": size, "domain": domain,
            "dns": bool(dns_name), "sni": bool(sni),
            "ipproto": proto_num, "transport": transport}


def service(port: str, transport: str = "") -> str:
    """Servicio del puerto; con el transporte a la vista, 443/udp es QUIC (HTTP/3)."""
    if transport == "udp" and port == "443":
        return "quic"
    return SERVICE_PORTS.get(port, port or "other")


def in_lan(ip: str) -> bool:
    if not LAN_NETS:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in LAN_NETS)


def _say(text: str) -> None:
    """print sin riesgo de UnicodeEncodeError (stdout de Windows sin consola UTF-8)."""
    try:
        print(text, flush=True)
    except UnicodeEncodeError:
        print(text.encode("ascii", "replace").decode(), flush=True)


def load_cdn(path: str | Path) -> int:
    """Carga la tabla IP->etiqueta. Devuelve cuántos prefijos quedan activos."""
    global _CDN, _CDN_ENABLED, _CDN_PATH, _CDN_MTIME, CDN_DEBUG
    _CDN, _CDN_ENABLED, _CDN_PATH = [], False, Path(path) if str(path) else None
    if not _CDN_PATH:
        return 0
    try:
        data = json.loads(_CDN_PATH.read_text(encoding="utf-8"))
        _CDN_MTIME = _CDN_PATH.stat().st_mtime
    except FileNotFoundError:
        _say(f"cdn: sin tabla en {_CDN_PATH} (respaldo por IP desactivado)")
        return 0
    except (OSError, ValueError) as exc:
        _say(f"aviso: tabla CDN {_CDN_PATH} ilegible: {exc}")
        return 0
    if isinstance(data, dict) and isinstance(data.get("debug"), bool):
        CDN_DEBUG = bool(data["debug"])   # depuración sin tocar la tarea programada
    if isinstance(data, dict) and data.get("enabled") is False:
        _say(f"cdn: tabla {_CDN_PATH} desactivada (enabled=false)")
        return 0
    table = data.get("prefixes") if isinstance(data, dict) and "prefixes" in data else data
    if not isinstance(table, dict):
        _say(f"aviso: tabla CDN {_CDN_PATH} sin mapa de prefijos")
        return 0
    parsed: list[tuple] = []
    for prefix, value in table.items():
        name = value.get("label") if isinstance(value, dict) else value
        if not isinstance(name, str) or not name.strip():
            continue
        try:
            net = ipaddress.ip_network(str(prefix).strip(), strict=False)
        except ValueError:
            _say(f"aviso: prefijo CDN inválido, se ignora: {prefix!r}")
            continue
        parsed.append((net, name.strip()))
    parsed.sort(key=lambda item: -item[0].prefixlen)   # prefijo más específico primero
    _CDN = parsed
    _CDN_ENABLED = bool(parsed)
    if parsed:
        _say(f"cdn: {len(parsed)} prefijos cargados de {_CDN_PATH}")
    return len(parsed)


def cdn_label(ip: str) -> str:
    """Etiqueta para un destino sin dominio: '' si no hay tabla o no hay coincidencia."""
    if not (_CDN_ENABLED and _CDN):
        return ""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    for net, name in _CDN:      # ya ordenada por especificidad
        if addr in net:
            return name
    return ""


def refresh_cdn() -> int:
    """Recarga la tabla si cambió el fichero (así se edita sin reiniciar el sensor)."""
    if not _CDN_PATH:
        return 0
    try:
        mtime = _CDN_PATH.stat().st_mtime
    except OSError:
        if _CDN_ENABLED:
            _say(f"cdn: {_CDN_PATH} desapareció; se desactiva el respaldo por IP")
            return load_cdn(_CDN_PATH)
        return 0
    if mtime == _CDN_MTIME:
        return len(_CDN)
    return load_cdn(_CDN_PATH)


def record(flow: dict) -> None:
    global _LAST_PACKET
    with _LOCK:
        if LAN_NETS:
            src_in, dst_in = in_lan(flow["src"]), in_lan(flow["dst"])
            if src_in == dst_in:   # LAN<->LAN o exterior<->exterior: no nos dice nada
                return
            outbound = src_in
        else:
            outbound = flow["src"] in _LOCAL_IPS
        peer = flow["dst"] if outbound else flow["src"]
        if not peer or (not LAN_NETS and peer in _LOCAL_IPS):
            return
        direction = "out" if outbound else "in"
        # The service port is the destination port outbound and the source port inbound.
        proto = f"{service(flow['dport'] if outbound else flow['sport'], flow.get('transport', ''))}/{direction}"
        # SNI/Host only exists in the outbound handshake; responses are matched by peer.
        observed = flow["domain"]
        is_dns = bool(flow.get("dns"))
        if observed and not is_dns:
            learn_peer(peer, observed)         # sólo nombres de conexión, no de consulta
        elif is_dns and _PEER_DOMAIN.get(peer) == observed:
            # Entrada contaminada por una versión anterior: el nombre de la consulta
            # había quedado pegado al servidor DNS (p. ej. 8.8.8.8 -> nrdp...).
            forget_peer(peer)
        # Un paquete DNS habla de la consulta, no del destino: ni hereda el mapa ni
        # publica el nombre consultado como dominio del servidor (ese nombre sí
        # cuenta en netviz_domain_bytes_total: los bytes son de esa consulta).
        domain = "" if is_dns else (observed or _PEER_DOMAIN.get(peer, ""))
        domain_name = observed if is_dns else domain
        # Respaldo: sólo cuando no hay dominio observado (SNI/Host). El dominio
        # manda siempre; la tabla de CDN no lo sobrescribe.
        cdn = "" if (domain or is_dns) else cdn_label(peer)
        client = flow["src"] if outbound else flow["dst"]
        ckey = (client, peer, domain, proto, cdn)
        centry = _CLIENTS.setdefault(ckey, [0, 0])
        centry[0] += flow["bytes"]
        centry[1] += 1
        key = (peer, domain, proto, cdn)
        entry = _FLOWS.setdefault(key, [0, 0])
        entry[0] += flow["bytes"]
        entry[1] += 1
        _COUNTERS["packets"] += 1
        _COUNTERS["bytes"] += flow["bytes"]
        if flow["dns"]:
            _COUNTERS["dns"] += 1
        if flow["sni"]:
            _COUNTERS["sni"] += 1
        if cdn:
            _COUNTERS["cdn"] += 1
            named = _CDN_BYTES.setdefault(cdn, [0, 0])
            named[0] += flow["bytes"]
            named[1] += 1
            if CDN_DEBUG and peer not in _CDN_SEEN:
                _CDN_SEEN.add(peer)
                _say(f"cdn: {peer} sin dominio -> '{cdn}' (cliente {client})")
        if domain_name:
            dom = _DOMAINS.setdefault(domain_name, [0, 0])
            dom[0] += flow["bytes"]
            dom[1] += 1
        dst = _DSTS.setdefault(peer, [0, 0])
        dst[0] += flow["bytes"]
        dst[1] += 1
        _LAST_PACKET = max(_LAST_PACKET, flow["ts"])
        if len(_FLOWS) > MAX_FLOWS or len(_DOMAINS) > MAX_DOMAINS:
            prune()


def prune() -> None:
    """Keep the heaviest entries so memory stays bounded on busy links."""
    if len(_FLOWS) > MAX_FLOWS:
        keep_flows = sorted(_FLOWS.items(), key=lambda kv: -kv[1][0])[: MAX_FLOWS // 2]
        _FLOWS.clear()
        _FLOWS.update(keep_flows)
    if len(_CLIENTS) > MAX_CLIENTS:
        keep_clients = sorted(_CLIENTS.items(), key=lambda kv: -kv[1][0])[: MAX_CLIENTS // 2]
        _CLIENTS.clear()
        _CLIENTS.update(keep_clients)
    if len(_DOMAINS) > MAX_DOMAINS:
        keep_domains = sorted(_DOMAINS.items(), key=lambda kv: -kv[1][0])[: MAX_DOMAINS // 2]
        _DOMAINS.clear()
        _DOMAINS.update(keep_domains)


# ------------------------------------------------------------------- capture
def capture_loop(iface: str) -> None:
    command = [TSHARK, "-i", iface, "-n", "-q", "-l", "-T", "fields",
               "-E", "separator=/t", "-E", "occurrence=f", "-f", BPF_FILTER]
    for field in FIELDS:
        command += ["-e", field]
    while True:
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True, bufsize=1)
            _STATUS["tshark"] = "running"
            _STATUS["detail"] = f"{' '.join(command[:4])} …"
            for line in process.stdout:  # type: ignore[union-attr]
                flow = parse_line(line)
                if flow:
                    record(flow)
            error = (process.stderr.read() if process.stderr else "") or ""
            _STATUS["tshark"] = "restarting"
            _STATUS["detail"] = error.strip()[-200:]
        except Exception as exc:  # noqa: BLE001
            _STATUS["tshark"] = "error"
            _STATUS["detail"] = f"{type(exc).__name__}: {exc}"
        time.sleep(5)


def load_names(path: str) -> None:
    """Carga ip -> {name, type} para etiquetar los flujos por dispositivo."""
    global _NAMES
    if not path:
        return
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        _NAMES = {str(ip): dict(info) for ip, info in data.items() if isinstance(info, dict)}
        print(f"nombres cargados: {len(_NAMES)} equipos", flush=True)
    except Exception as exc:  # noqa: BLE001
        print(f"aviso: no pude leer {path}: {exc}", flush=True)


def maintenance_loop(iface: str) -> None:
    global _LOCAL_IPS
    while True:
        _LOCAL_IPS = local_ips(iface)
        refresh_cdn()
        prune_peers()
        save_peers()          # vuelca lo aprendido: un reinicio no borra los nombres
        with _LOCK:
            targets = [ip for ip, (b, _p) in sorted(_DSTS.items(), key=lambda kv: -kv[1][0])[:40]]
        geolocate(targets)
        time.sleep(30)


# -------------------------------------------------------------------- metrics
def label(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def render() -> str:
    with _LOCK:
        flows = sorted(_FLOWS.items(), key=lambda kv: -kv[1][0])[:200]
        domains = sorted(_DOMAINS.items(), key=lambda kv: -kv[1][0])[:200]
        dsts = sorted(_DSTS.items(), key=lambda kv: -kv[1][0])[:200]
        counters = dict(_COUNTERS)
        last = _LAST_PACKET
        status = dict(_STATUS)
        cdn_bytes = {name: list(vals) for name, vals in _CDN_BYTES.items()}
        geo = {ip: dict(_GEO.get(ip, {})) for ip, _ in dsts}
    lines = [
        "# HELP netviz_capture_up 1 when tshark is capturing.",
        "# TYPE netviz_capture_up gauge",
        f'netviz_capture_up {1 if status.get("tshark") == "running" else 0}',
        "# HELP netviz_capture_packets_total Packets seen on the captured interface.",
        "# TYPE netviz_capture_packets_total counter",
        f"netviz_capture_packets_total {counters['packets']}",
        "# HELP netviz_capture_bytes_total Bytes seen on the captured interface.",
        "# TYPE netviz_capture_bytes_total counter",
        f"netviz_capture_bytes_total {counters['bytes']}",
        "# HELP netviz_capture_dns_packets_total DNS packets observed (queries and answers).",
        "# TYPE netviz_capture_dns_packets_total counter",
        f"netviz_capture_dns_packets_total {counters['dns']}",
        "# HELP netviz_capture_sni_packets_total TLS ClientHello packets carrying SNI.",
        "# TYPE netviz_capture_sni_packets_total counter",
        f"netviz_capture_sni_packets_total {counters['sni']}",
        "# HELP netviz_capture_last_packet_timestamp_seconds Timestamp of the newest captured packet.",
        "# TYPE netviz_capture_last_packet_timestamp_seconds gauge",
        f"netviz_capture_last_packet_timestamp_seconds {last:.3f}",
        "# HELP netviz_flow_bytes_total Bytes per destination/domain flow.",
        "# TYPE netviz_flow_bytes_total counter",
    ]
    for (dst, domain, proto, cdn), (size, packets) in flows:
        labels = f'dst="{label(dst)}",domain="{label(domain)}",proto="{label(proto)}"'
        if cdn:
            labels += f',cdn="{label(cdn)}"'
        lines.append(f"netviz_flow_bytes_total{{{labels}}} {size}")
        lines.append(f"netviz_flow_packets_total{{{labels}}} {packets}")
    lines += [
        "# HELP netviz_client_bytes_total Bytes per LAN client, destination and domain.",
        "# TYPE netviz_client_bytes_total counter",
    ]
    with _LOCK:
        clients = sorted(_CLIENTS.items(), key=lambda kv: -kv[1][0])[:300]
    for (client, dst, domain, proto, cdn), (size, packets) in clients:
        info = _NAMES.get(client, {})
        name = info.get("name") or "desconocido"
        dtype = info.get("type") or "desconocido"
        labels = (f'client="{label(client)}",name="{label(name)}",type="{label(dtype)}",'
                  f'dst="{label(dst)}",domain="{label(domain)}",proto="{label(proto)}"')
        if cdn:
            labels += f',cdn="{label(cdn)}"'
        lines.append(f"netviz_client_bytes_total{{{labels}}} {size}")
    lines += [
        "# HELP netviz_cdn_named_bytes_total Bytes named by the IP->CDN table fallback (flows without domain).",
        "# TYPE netviz_cdn_named_bytes_total counter",
    ]
    for cdn, (size, packets) in sorted(cdn_bytes.items(), key=lambda kv: -kv[1][0]):
        lines.append(f'netviz_cdn_named_bytes_total{{cdn="{label(cdn)}"}} {size}')
        lines.append(f'netviz_cdn_named_packets_total{{cdn="{label(cdn)}"}} {packets}')
    lines += [
        "# HELP netviz_domain_bytes_total Bytes per observed domain (DNS, SNI or Host header).",
        "# TYPE netviz_domain_bytes_total counter",
    ]
    for domain, (size, packets) in domains:
        lines.append(f'netviz_domain_bytes_total{{domain="{label(domain)}"}} {size}')
        lines.append(f'netviz_domain_packets_total{{domain="{label(domain)}"}} {packets}')
    lines += [
        "# HELP netviz_capture_destination_bytes_total Bytes per destination with approximate location.",
        "# TYPE netviz_capture_destination_bytes_total counter",
    ]
    for dst, (size, packets) in dsts:
        info = geo.get(dst) or {}
        if info.get("lat") is None:
            labels = f'dst="{label(dst)}",city="",country=""'
        else:
            labels = (f'dst="{label(dst)}",lat="{info["lat"]}",lon="{info["lon"]}",'
                      f'city="{label(info.get("city", ""))}",country="{label(info.get("country", ""))}"')
        lines.append(f"netviz_capture_destination_bytes_total{{{labels}}} {size}")
    return "\n".join(lines) + "\n"


class Handler(BaseHTTPRequestHandler):
    server_version = "netviz-capture/1.0"

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/metrics":
            body = render().encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        elif self.path == "/healthz":
            body = json.dumps({
                **_STATUS,
                "lan": [str(n) for n in LAN_NETS],
                "names": len(_NAMES),
                "local_ips": sorted(_LOCAL_IPS),
                "clients": len({k[0] for k in _CLIENTS}),
                "cdn": {
                    "enabled": _CDN_ENABLED,
                    "prefixes": len(_CDN),
                    "file": str(_CDN_PATH) if _CDN_PATH else None,
                    "debug": CDN_DEBUG,
                    "named_packets": _COUNTERS.get("cdn", 0),
                },
                "peers": {
                    "learned": len(_PEER_DOMAIN),
                    "file": str(PEERS_CACHE),
                    "ttl_hours": round(PEERS_TTL / 3600, 1),
                },
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        else:
            body = b"not found\n"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A002
        return


def main() -> None:
    global _LOCAL_IPS, LISTEN_PORT, BIND_ADDR, TSHARK, LAN_NETS, PEERS_CACHE, PEERS_TTL
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", default=os.getenv("NETVIZ_IFACE", "en0"))
    parser.add_argument("--port", type=int, default=LISTEN_PORT)
    parser.add_argument("--bind", default=BIND_ADDR, help="dirección de escucha (0.0.0.0 para acceso remoto)")
    parser.add_argument("--tshark", default=TSHARK, help="ruta al ejecutable de tshark")
    parser.add_argument("--names", default=os.getenv("NETVIZ_NAMES", ""),
                        help="JSON ip -> {name, type} para etiquetar por dispositivo")
    parser.add_argument("--lan", default=os.getenv("NETVIZ_LAN", ""),
                        help="rango de la LAN (p. ej. 192.0.2.0/24) cuando se captura de un puerto espejo")
    parser.add_argument("--cdn", default=os.getenv("NETVIZ_CDN_FILE", ""),
                        help="tabla JSON IP->etiqueta para nombrar destinos sin dominio "
                             "(por defecto cdn-map.json junto al sensor, si existe)")
    parser.add_argument("--no-cdn", dest="no_cdn", action="store_true",
                        help="desactiva el respaldo por tabla de CDN aunque exista el fichero")
    parser.add_argument("--peers", default=os.getenv("NETVIZ_PEERS_FILE", ""),
                        help="JSON donde se guardan los nombres IP->dominio aprendidos "
                             "(por defecto STATE_DIR/peers.json)")
    parser.add_argument("--peers-ttl-h", type=float, default=None,
                        help="caducidad en horas de IP->dominio (por defecto 36, env NETVIZ_PEERS_TTL_H)")
    parser.add_argument("--replay", help="read tshark -T fields lines from a file instead of capturing")
    args = parser.parse_args()

    LISTEN_PORT = args.port
    BIND_ADDR = args.bind
    if args.tshark:
        TSHARK = args.tshark
    if args.lan:
        LAN_NETS = [ipaddress.ip_network(n.strip(), strict=False)
                    for n in args.lan.split(",") if n.strip()]
    load_names(args.names)
    if args.no_cdn:
        _say("cdn: respaldo por IP desactivado (--no-cdn)")
    else:
        load_cdn(args.cdn or (Path(__file__).resolve().parent / "cdn-map.json"))
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    if args.peers:
        PEERS_CACHE = Path(args.peers)
    if args.peers_ttl_h is not None:
        PEERS_TTL = max(0.0, args.peers_ttl_h) * 3600
    _LOCAL_IPS = local_ips(args.iface)
    load_geo()
    load_peers()          # los nombres ya vistos sobreviven al reinicio

    if args.replay:
        for line in Path(args.replay).read_text().splitlines():
            flow = parse_line(line)
            if flow:
                record(flow)
        save_peers(force=True)
        _STATUS["tshark"] = "replay"
    else:
        threading.Thread(target=capture_loop, args=(args.iface,), daemon=True).start()
        threading.Thread(target=maintenance_loop, args=(args.iface,), daemon=True).start()

    server = ThreadingHTTPServer((BIND_ADDR, LISTEN_PORT), Handler)
    print(f"netviz capture on {args.iface}: http://{BIND_ADDR}:{LISTEN_PORT}/metrics", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
