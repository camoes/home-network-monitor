#!/usr/bin/env python3
"""Prueba activa del proxy DHCP.

Envía un DHCPDISCOVER desde este Mac (MAC ficticia), escucha la respuesta y
muestra la IP ofrecida y el DNS anunciado. Sirve para distinguir entre
"el proxy no funciona" y "el dispositivo no ha pedido concesión".
"""

from __future__ import annotations

import argparse
import random
import socket
import struct
import sys
import time

OPTIONS = {
    "1": "máscara", "3": "puerta de enlace", "6": "DNS", "15": "dominio",
    "28": "broadcast", "51": "lease_time", "54": "servidor DHCP",
}


def build_discover(mac: bytes, xid: bytes) -> bytes:
    packet = struct.pack("!BBBBIHH", 1, 1, 6, 0, int.from_bytes(xid, "big"), 0, 0x8000)
    packet += b"\x00" * 16          # ciaddr
    packet += b"\x00" * 16          # yiaddr
    packet += b"\x00" * 16          # siaddr
    packet += b"\x00" * 16          # giaddr
    packet += mac + b"\x00" * 10    # chaddr (16)
    packet += b"\x00" * 192         # sname
    packet += b"\x00" * 64          # file
    packet += b"\x63\x82\x53\x63"   # magic cookie
    packet += bytes([53, 1, 1])     # DHCPDISCOVER
    packet += bytes([55, 4, 1, 3, 6, 15])  # parameter request list
    packet += b"\xff"
    return packet


def parse_reply(data: bytes) -> dict:
    info = {"yiaddr": socket.inet_ntoa(data[16:20]),
            "server": "", "options": {}}
    i = 240
    while i < len(data):
        code = data[i]
        if code == 255:
            break
        if code == 0:
            i += 1
            continue
        length = data[i + 1]
        value = data[i + 2:i + 2 + length]
        if code == 6 and len(value) >= 4:
            info["options"]["DNS"] = ", ".join(
                socket.inet_ntoa(value[j:j + 4]) for j in range(0, len(value), 4))
        elif code == 54 and len(value) == 4:
            info["server"] = socket.inet_ntoa(value)
        elif code == 3 and len(value) >= 4:
            info["options"]["puerta"] = socket.inet_ntoa(value[:4])
        elif code == 1 and len(value) == 4:
            info["options"]["máscara"] = socket.inet_ntoa(value)
        elif code == 51 and len(value) == 4:
            info["options"]["lease"] = f"{int.from_bytes(value, 'big') // 3600} h"
        i += 2 + length
    return info


def main() -> int:
    parser = argparse.ArgumentParser(description="Prueba activa del proxy DHCP")
    parser.add_argument("--port", type=int, default=1068,
                        help="puerto local de escucha (68 requiere root, como un cliente real)")
    args = parser.parse_args()
    local_port = args.port
    mac = bytes([0x02, 0x00] + [random.randrange(256) for _ in range(4)])
    xid = bytes(random.randrange(256) for _ in range(4))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(("", local_port))
    sock.settimeout(5)

    packet = build_discover(mac, xid)
    print(f"MAC de prueba: {':'.join(f'{b:02x}' for b in mac)}  puerto local: {local_port}")
    sock.sendto(packet, ("255.255.255.255", 67))
    print("DHCPDISCOVER enviado; esperando respuesta 5 s…")

    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            data, addr = sock.recvfrom(2048)
        except socket.timeout:
            break
        if len(data) < 240 or data[4:8] != xid:
            continue
        reply = parse_reply(data)
        print(f"\nrespuesta de {addr[0]}:")
        print(f"  IP ofrecida : {reply['yiaddr']}")
        print(f"  servidor    : {reply['server'] or '(sin opción 54)'}")
        for name, value in reply["options"].items():
            print(f"  {name:11}: {value}")
        dns = reply["options"].get("DNS", "")
        if dns:
            print("\nRESULTADO:", "proxy OK (DNS inyectado)" if "192.0.2.10" in dns
                  else "respuesta sin el DNS de AdGuard: el proxy no intervino")
        return 0

    print("\nRESULTADO: sin respuesta. Ni el router ni el proxy contestaron al DISCOVER.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
