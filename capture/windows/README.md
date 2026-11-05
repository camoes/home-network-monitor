# Sensor de captura en Windows (Perdigon)

Captura pasiva en un equipo Windows enchufado al **puerto espejo** de un switch
gestionable. Expone `:9101/metrics` para Prometheus.

## Requisitos

- Python 3.12 — `winget install --id Python.Python.3.12 -e`
- Wireshark (tshark/dumpcap) — `winget install --id WiresharkFoundation.Wireshark -e`
- Npcap — **sólo por el asistente gráfico**. La edición gratuita no admite `/S`
  (el instalador responde *"silent mode installation is only supported for Npcap
  OEM"* y sale con código 0 sin instalar nada). Marcar
  **“Install Npcap in WinPcap API-compatible Mode”**.

Comprobar después: `tshark -D` debe listar `(Ethernet)` y no quejarse de
`wpcap.dll`.

## Instalación

```powershell
# desde el Mac
python3 ~/Repos/net-conn/remote.py copy equipo capture/sensor.py netviz-capture/sensor.py
python3 ~/Repos/net-conn/remote.py copy equipo capture/cdn-map.json netviz-capture/cdn-map.json
python3 ~/Repos/net-conn/remote.py copy equipo capture/windows/install-capture-windows.ps1 netviz-capture/install.ps1
python3 ~/Repos/net-conn/remote.py run equipo "powershell -NoProfile -ExecutionPolicy Bypass -File netviz-capture\install.ps1 -Adapter Ethernet -Port 9101"
```

El script:

1. localiza `python.exe` (incluido el de `%LOCALAPPDATA%\Programs\Python3xx`).
2. resuelve el dispositivo NPF a partir del nombre del adaptador (`tshark -D`).
3. registra la tarea **`netviz-capture`** (al iniciar sesión, privilegios altos) y
   la arranca, pasando `--tshark` con la ruta completa.
4. crea la regla de firewall para **TCP 9101 sólo desde `192.0.2.0/24`**.
5. consulta `/healthz` y muestra la URL de métricas.

## Detalles que cuestan un rato si no se saben

- **`tshark` no está en el PATH** tras instalar Wireshark: hay que pasar la ruta
  completa (`--tshark "C:\Program Files\Wireshark\tshark.exe"`).
- **Comillas simples no son comillas en Windows**: `--iface '\Device\NPF_{...}'`
  llega al proceso con las comillas dentro y tshark falla con *"El nombre de
  archivo, el nombre de directorio o la sintaxis de la etiqueta del volumen no son
  correctos (123)"*. Sin comillas funciona.
- El sensor escucha en `127.0.0.1` por defecto; para que Prometheus lo consulte
  desde otro equipo hay que pasar `--bind 0.0.0.0`.

## Verificación

```bash
curl -s http://192.0.2.46:9101/healthz     # {"tshark": "running", ...}
curl -s http://192.0.2.46:9101/metrics | grep netviz_capture_bytes_total
```

En Prometheus, job `netviz-capture`, label `sensor=equipo`.

## Nombres para flujos sin dominio (respaldo IP→CDN)

La tele abre vídeo por QUIC/HTTP-3 y esos flujos no llevan SNI legible: salen con
`domain=""`. El sensor admite una tabla `cdn-map.json` **junto a `sensor.py`**
(por eso la tarea programada no cambia de argumentos) que nombra el destino por
IP/prefijo y publica el resultado en el label `cdn`:

- el dominio observado (SNI/Host/DNS) **siempre gana**; la tabla sólo rellena vacíos;
- si el fichero no existe, `"enabled": false` o el sensor arranca con `--no-cdn`,
  el comportamiento es el de siempre (label `cdn` ausente);
- se relee solo si cambia el fichero: se edita sin reiniciar el sensor;
- `NETVIZ_CDN_DEBUG=1` (variable de entorno) loguea cada destino nuevo; `/healthz`
  muestra el estado en `cdn`.

Revertir = poner `"enabled": false` (o borrar el fichero en Perdigon). Sin tabla,
la etiqueta desaparece del panel y no hay nada más que deshacer.

## Nombres IP→dominio entre reinicios (`peers.json`)

El mapa `IP del destino -> dominio` que el sensor aprende del SNI/Host se guarda
en `C:\Users\usuario\.netviz-capture\peers.json` (es `STATE_DIR`, el mismo sitio que
`geo.json`; se puede mover con `NETVIZ_CAPTURE_STATE` o `--peers`) y se carga al
arrancar. Consecuencia práctica en este equipo: tras reiniciar la tarea, los
flujos que ya se habían nombrado (p. ej. `142.251.151.4 -> www.youtube.com`) salen
atribuidos desde el primer paquete en vez de quedarse en `domain=""` hasta el
siguiente ClientHello. Las entradas caducan a las 36 h (`--peers-ttl-h`) para no
heredar dominios de IPs de CDN recicladas, y **las consultas DNS no crean
entradas**: el nombre consultado no se pega al servidor DNS. Borrar el fichero
olvida todo; `/healthz` lo resume en `peers: {learned, file, ttl_hours}`.

## Puerto espejo y dirección del tráfico

Sin **port mirroring** en el switch, el equipo sólo ve su propio tráfico.

Mapa de puertos de esta instalación (TL-SG108PE):

| Puerto | Qué hay | Enlace |
| --- | --- | --- |
| 2 | Perdigon (captura) | 1 Gbps |
| 3 | televisión (LG) | 100 Mbps |
| 4 | router | 1 Gbps |

**Configuración correcta:** *Mirroring Port* = **2** (PC), *Mirrored Port* = **4**
(router), Ingress + Egress. Da el tráfico a internet de todos los equipos cableados.

**Lo que NO se debe hacer:** invertirlo (destino 4, origen 2). El switch duplica el
tráfico del PC hacia el router y la red del PC se degrada hasta caer (SSH y métricas
mueren). Costó dos cortes descubrirlo: el mapa de puertos estaba al revés.

**Wi-Fi:** los equipos inalámbricos no pasan por el puerto del router en el switch,
así que no se capturan. De ellos sólo hay DNS si usan AdGuard.

Con espejo hay que pasar `--lan <red>` al sensor. Si no, decide la dirección
comparando con las IPs del propio PC, y en un puerto espejo ninguna IP del flujo
es suya: etiquetaría casi todo como entrante y la geolocalización saldría mal.

```powershell
... -File netviz-capture\install.ps1 -Adapter Ethernet -Port 9101 -Lan 192.0.2.0/24
```

Con `--lan`, la dirección se decide por pertenencia a la red: origen dentro =
`/out`, destino dentro = `/in`, y LAN↔LAN se descarta.

La tarea queda **sin disparador**: no arranca sola, se levanta bajo demanda desde
el portátil (ver `make sensor-up` en el README del proyecto). Así el equipo sólo
captura cuando se está monitorizando.

`sshd` sí es independiente, pero necesita la sesión iniciada: si el equipo se queda
en la pantalla de bloqueo, no hay acceso remoto ni forma de arrancar el sensor.
