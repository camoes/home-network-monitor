#!/bin/bash
# Supervisor del proxy DHCP.
#
# Genera la configuración con la IP actual del Mac, arranca dnsmasq y lo
# reinicia si la IP de la interfaz cambia (el router reparte por DHCP y el Mac
# puede recibir otra dirección). Si no hay IP, espera sin tocar la red.
#
# Pensado para ejecutarse como root (puerto 67), normalmente desde el
# LaunchDaemon com.usuario.dhcp-proxy.

set -u

IFACE="${1:-en0}"
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
TEMPLATE="$BASE_DIR/dnsmasq.conf.template"
RUNTIME_CONF="/tmp/netviz-dhcp-proxy.conf"
DNSMASQ="/opt/homebrew/sbin/dnsmasq"

if [ ! -x "$DNSMASQ" ]; then
  echo "dnsmasq no encontrado en $DNSMASQ (brew install dnsmasq)" >&2
  exit 1
fi

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

LOGFILE="/tmp/netviz-dhcp-proxy.log"
# Permisos legibles para diagnosticar sin sudo (dnsmasq escribiría 0660 nobody:wheel).
: > "$LOGFILE" 2>/dev/null || true
chmod 0644 "$LOGFILE" 2>/dev/null || true

while true; do
  IP="$(/usr/sbin/ipconfig getifaddr "$IFACE" 2>/dev/null || true)"
  if [ -z "$IP" ]; then
    log "interfaz $IFACE sin IP; reintentando en 15 s"
    sleep 15
    continue
  fi

  sed -e "s/__IFACE__/$IFACE/" -e "s/__DNS_IP__/$IP/" "$TEMPLATE" > "$RUNTIME_CONF"
  if ! "$DNSMASQ" --test -C "$RUNTIME_CONF" >/dev/null 2>&1; then
    log "configuración inválida, no arranco: $RUNTIME_CONF"
    sleep 30
    continue
  fi

  log "arrancando proxy DHCP en $IFACE (DNS anunciado: $IP)"
  "$DNSMASQ" -C "$RUNTIME_CONF" -k >> "$LOGFILE" 2>&1 &
  PID=$!

  while kill -0 "$PID" 2>/dev/null; do
    sleep 30
    NOW="$(/usr/sbin/ipconfig getifaddr "$IFACE" 2>/dev/null || true)"
    if [ "$NOW" != "$IP" ]; then
      log "la IP cambió ($IP -> ${NOW:-ninguna}); reiniciando proxy"
      kill "$PID" 2>/dev/null
      break
    fi
  done
  wait "$PID" 2>/dev/null
  sleep 3
done
