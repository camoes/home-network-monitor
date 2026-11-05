#!/bin/bash
# Diagnóstico del stack y de los componentes nativos. Solo lectura.
set -u
cd "$(dirname "$0")/.." || exit 1

ok() { printf "  \033[32m✓\033[0m %s\n" "$1"; }
warn() { printf "  \033[33m!\033[0m %s\n" "$1"; }
bad() { printf "  \033[31m✗\033[0m %s\n" "$1"; }

echo "== contenedores =="
docker compose ps --services --filter status=running 2>/dev/null | sed 's/^/  /'
missing=$(docker compose ps --services 2>/dev/null | while read -r s; do
  docker compose ps --services --filter status=running 2>/dev/null | grep -qx "$s" || echo "$s"
done)
if [ -z "$missing" ]; then ok "todos los servicios en marcha"; else bad "parados: $missing"; fi

echo
echo "== endpoints =="
for url in http://127.0.0.1:9090/-/healthy http://127.0.0.1:9093/-/healthy \
           http://127.0.0.1:3000/api/health http://127.0.0.1:8080/healthz; do
  code=$(curl -s -o /dev/null -m 3 -w '%{http_code}' "$url" || true)
  if [ "$code" = "200" ]; then ok "$url"; else bad "$url -> ${code:-sin respuesta}"; fi
done

echo
echo "== sensor de captura =="
if pgrep -f "capture/sensor.py" >/dev/null 2>&1; then
  ok "sensor en marcha ($(curl -s -m 2 http://127.0.0.1:9101/healthz 2>/dev/null | head -c 60))"
elif launchctl print gui/$(id -u)/com.usuario.netviz-capture >/dev/null 2>&1; then
  ok "LaunchAgent cargado"
else
  warn "sensor parado (make install-capture o python3 capture/sensor.py --iface en0)"
fi

echo
echo "== proxy DHCP =="
count=$(pgrep -f "netviz-dhcp-proxy.conf" 2>/dev/null | wc -l | tr -d ' ')
case "$count" in
  0) warn "no hay proxy en marcha (make proxy)" ;;
  1) ok "una instancia de dnsmasq" ;;
  *) bad "$count instancias de dnsmasq: pueden duplicar respuestas (make proxy-stop && make proxy)" ;;
esac
if [ -r /tmp/netviz-dhcp-proxy.log ]; then
  lines=$(grep -cE "DHCP(ACK|OFFER|DISCOVER|REQUEST)" /tmp/netviz-dhcp-proxy.log 2>/dev/null || true)
  if [ "${lines:-0}" -gt 0 ] 2>/dev/null; then
    echo "  últimas concesiones:"
    grep -E "DHCP(ACK|OFFER|DISCOVER|REQUEST)" /tmp/netviz-dhcp-proxy.log 2>/dev/null | tail -3 | sed 's/^/    /'
  else
    echo "  (sin tráfico DHCP todavía: los equipos renuevan a las ~12 h o al reconectar)"
  fi
fi

echo
echo "== AdGuard =="
if [ -f adguard.env ]; then
  set -a; . ./adguard.env; set +a
  curl -s -u "$AGH_USER:$AGH_PASS" http://127.0.0.1/control/stats 2>/dev/null | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
except Exception:
    print('  no se pudo leer /control/stats'); raise SystemExit
tc=d.get('top_clients') or []
if isinstance(tc, dict): tc=sorted(tc.items(), key=lambda x:-x[1])
ips=[]
for c in tc:
    if isinstance(c, dict) and c: ips.append(next(iter(c)))
    elif isinstance(c, (list, tuple)) and c: ips.append(c[0])
    elif isinstance(c, str): ips.append(c)
print(f\"  consultas: {d.get('num_dns_queries')} | bloqueadas: {d.get('num_blocked_filtering')} | clientes: {ips[:6]}\")
"
else
  warn "falta adguard.env"
fi

echo
echo "== dispositivos con DNS visible =="
curl -s -m 5 'http://127.0.0.1:8080/api/privacy?hours=24' 2>/dev/null | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
except Exception:
    print('  dns-map sin respuesta'); raise SystemExit
vis=[x for x in d['devices'] if not x['silent']]
print(f\"  {len(vis)} de {len(d['devices'])} equipos con consultas\")
for x in vis[:6]:
    print(f\"    {x['name']} ({x['ip']}): {x['hits']} consultas\")
" || true
