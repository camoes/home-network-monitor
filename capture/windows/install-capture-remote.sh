#!/bin/bash
# Instala y arranca el sensor de captura en el host remoto.
# Se ejecuta EN el host remoto (lo lanza remote.py run o make equipo).
#
#   ./install-capture-remote.sh <interfaz> [puerto]
set -u

IFACE="${1:-}"
PORT="${2:-9101}"
APP_DIR="$HOME/netviz-capture"

if [ -z "$IFACE" ]; then
  echo "uso: $0 <interfaz> [puerto]" >&2
  echo "interfaces disponibles:" >&2
  if command -v ip >/dev/null 2>&1; then ip -o link show | awk -F': ' '{print "  " $2}'; else ifconfig -l 2>/dev/null | tr ' ' '\n' | sed 's/^/  /'; fi
  exit 1
fi

if ! command -v tshark >/dev/null 2>&1; then
  echo "tshark no está instalado. Instálalo primero:" >&2
  echo "  Debian/Ubuntu: sudo apt install tshark" >&2
  echo "  Fedora:        sudo dnf install wireshark-cli" >&2
  echo "  Arch:          sudo pacman -S wireshark-cli" >&2
  echo "  macOS:         brew install --cask wireshark" >&2
  exit 1
fi

mkdir -p "$APP_DIR"

OS="$(uname -s)"
echo "sistema: $OS · interfaz: $IFACE · puerto: $PORT"

case "$OS" in
  Linux)
    UNIT_DIR="$HOME/.config/systemd/user"
    mkdir -p "$UNIT_DIR"
    cat > "$UNIT_DIR/netviz-capture.service" <<EOF
[Unit]
Description=netviz packet capture sensor
After=network-online.target

[Service]
ExecStart=/usr/bin/env python3 $APP_DIR/sensor.py --iface $IFACE --port $PORT
Environment=NETVIZ_TSHARK=$(command -v tshark)
Environment=NETVIZ_CAPTURE_STATE=$APP_DIR/state
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
EOF
    systemctl --user daemon-reload 2>/dev/null || true
    if systemctl --user enable --now netviz-capture.service 2>/dev/null; then
      echo "servicio systemd de usuario activo (netviz-capture)"
      echo "nota: para que arranque sin sesión abierta: sudo loginctl enable-linger $USER"
    else
      echo "systemd de usuario no disponible; arrancando con nohup (no persiste tras reinicio)"
      ( cd "$APP_DIR" && setsid nohup python3 sensor.py --iface "$IFACE" --port "$PORT" \
          > "$APP_DIR/sensor.log" 2>&1 & )
    fi
    ;;
  Darwin)
    PLIST="$HOME/Library/LaunchAgents/com.usuario.netviz-capture.plist"
    mkdir -p "$HOME/Library/LaunchAgents"
    cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.usuario.netviz-capture</string>
  <key>ProgramArguments</key><array>
    <string>/usr/bin/python3</string><string>-u</string>
    <string>$APP_DIR/sensor.py</string>
    <string>--iface</string><string>$IFACE</string>
    <string>--port</string><string>$PORT</string>
  </array>
  <key>EnvironmentVariables</key><dict>
    <key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    <key>NETVIZ_CAPTURE_STATE</key><string>$APP_DIR/state</string>
  </dict>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/tmp/netviz-capture.log</string>
  <key>StandardErrorPath</key><string>/tmp/netviz-capture.err</string>
</dict></plist>
EOF
    launchctl bootout "gui/$(id -u)/com.usuario.netviz-capture" 2>/dev/null || true
    launchctl bootstrap "gui/$(id -u)" "$PLIST" && echo "LaunchAgent cargado"
    ;;
  *)
    echo "sistema no soportado: $OS" >&2
    exit 1
    ;;
esac

sleep 2
if command -v curl >/dev/null 2>&1; then
  curl -s -m 3 "http://127.0.0.1:$PORT/healthz" && echo
fi
echo "sensor instalado en $APP_DIR · métricas en http://<ip-del-host>:$PORT/metrics"
