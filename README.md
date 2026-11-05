# monitor-internet · monitorización doméstica

Stack local para responder tres preguntas sobre tu red: **¿qué velocidad tengo
contratada frente a la medida?**, **¿qué dispositivos hay conectados y de qué tipo
son?** y **¿qué dominios consulta cada uno, dentro y fuera de casa?**

Todo corre en tu máquina y se publica solo en `127.0.0.1`: nada sale a la nube.

## Estado actual

Lo que funciona y está verificado:

| Pieza | Estado |
| --- | --- |
| Stack Docker (Prometheus, Grafana, Alertmanager, dns-map, exporters) | funcionando |
| Inventario del router y tipología de dispositivos | funcionando (15-21 equipos) |
| Mapa DNS con geolocalización | funcionando (AdGuard + Esri, sin API key) |
| Sensor de captura en Perdigon (`192.0.2.46:9101`) | funcionando, bajo demanda |
| Espejo del switch | **puerto 4 (router) → puerto 2 (PC)** |

Dos límites que conviene tener presentes, porque condicionan lo que se ve:

- Se captura el tráfico a internet de los equipos **cableados** (tele, PC, y lo que se
  enchufe al switch). Los equipos **Wi-Fi** no pasan por ese puerto: de ellos sólo hay
  DNS, y sólo si usan AdGuard.
- El espejo va del **puerto 4 (router) al 2 (PC)**. Al revés (2 → 4) se duplica el
  tráfico del PC hacia el router y la red del PC se degrada hasta caer.

## Arquitectura

```
   router ZTE 192.0.2.1 · API web (login + menuData)
        │ router.env
        ▼
   router-exporter :9800 ── inventario de dispositivos + contadores WAN
        │                            │
        │                            ▼
        │                     prometheus :9090 ◀── speedtest / ping / blackbox
        │                            │                    ▲
        ▼                            ▼                    │
   dns-map :8080 ────────────▶ grafana :3000        contrato ISP
   (AdGuard querylog + geo + mapa)   (dashboards provisionados)

   Nativos de macOS (fuera de Docker, opcionales):
     capture/sensor.py  · tshark → :9101 → Prometheus
     dhcp-proxy/        · anuncia AdGuard como DNS sin tocar el DHCP del router
```

## Requisitos

- Docker Desktop (o Docker Engine + Compose v2).
- `make`, `python3` (tests) y `curl`.
- Opcional en macOS: `tshark` (captura, grupo `access_bpf`) y `dnsmasq` (proxy DHCP).
- AdGuard Home en el host con DNS en `:53` y API en `:80`, con usuario y contraseña.

## Puesta en marcha

```bash
make env            # crea .env, router.env, adguard.env y device-overrides.csv
$EDITOR .env        # GRAFANA_ADMIN_PASSWORD y los Mbps de tu plan
$EDITOR router.env  # usuario/contraseña del router
$EDITOR adguard.env # usuario/contraseña de AdGuard
make up             # construye, arranca y muestra el estado
```

Despliegue completo (stack + diagnóstico):

```bash
make bootstrap      # pide sudo para el proxy DHCP; termina con make doctor
make doctor         # contenedores, endpoints, proxy, sensor y DNS
```

Captura en Perdigon (sensor del puerto espejo, bajo demanda):

```bash
make sensor-status   # tarea + /healthz
make sensor-up       # arranca y verifica que tshark captura
make sensor-down     # la para
```

El sensor **no arranca solo**: se levanta cuando lo pides. Requiere que la sesión de
Windows esté iniciada (igual que `sshd`, que se ejecuta como tarea `OpenSSH-User`).

Para refrescar los nombres y tipos de dispositivo que etiquetan los flujos:

```bash
python3 scripts/build-device-names.py    # escribe capture/devices.json
python3 ~/Repos/net-conn/remote.py copy equipo capture/devices.json netviz-capture/devices.json
```

## Agentes y tablero (Kanban)

El trabajo se registra en el tablero `monitor-internet`, con un perfil por rol para
que se vea quién tiene qué:

| Perfil | Rol | Tareas típicas |
| --- | --- | --- |
| `infra` | Red y equipos | switch, sensor en Perdigon, SSH, espejo de puertos |
| `analista` | Datos y observabilidad | PromQL, dashboards de Grafana, dns-map, inventario |
| `verificador` | Control de calidad | validar cambios, comprobar que no hay secretos en el paquete |
| `default` | Orquestación | documentación, empaquetado, decisiones de diseño |

```bash
hermes kanban list                    # estado del tablero
hermes kanban assign <tarea> infra    # reasignar
hermes -p infra                       # abrir sesión como ese perfil
```

El gateway despacha las tareas listas cada 60 s (`kanban.dispatch_in_gateway`), así
que se ejecutan en paralelo en workspaces aislados.

## Espejo del switch (TL-SG108PE)

*Monitoring → Port Mirror*:

- **Mirroring Port** (donde está el PC de captura): **2**
- **Mirrored Port** (lo que se copia): **4** (router). Marcar Ingress y Egress.
- **Port Mirror**: Enable.

Mapa real: **2 = PC**, **3 = tele**, **4 = router**. Invertir origen y destino (2 → 4)
duplica el tráfico del PC hacia el router y tumba su red.

| Servicio | URL | Para qué |
| --- | --- | --- |
| Grafana | http://127.0.0.1:3000 | velocidad, DNS por dispositivo y flujos |
| Mapa DNS | http://127.0.0.1:8080 | mapa mundial, topología, privacidad |
| Prometheus | http://127.0.0.1:9090 | series y estado de los targets |
| Alertmanager | http://127.0.0.1:9093 | alertas |
| Sensor (nativo) | http://127.0.0.1:9101/healthz | salud de la captura |

Otros comandos: `make status`, `make logs S=grafana`, `make test`, `make reload`,
`make down`, `make clean` (borra volúmenes: pierde el histórico).

## Qué mide cada pieza

- **Velocidad** — Ookla cada 30 min contra el plan de `.env`; alerta si baja del
  80 % durante 10 minutos.
- **Red** — latencia, pérdida de paquetes y disponibilidad HTTP (blackbox).
- **Router** — contadores acumulados de la WAN `FTTH-Data` e inventario de equipos
  conectados (MAC, IP, hostname, SSID o puerto LAN).
- **DNS** — consultas por dispositivo desde el query log de AdGuard, con
  clasificación del equipo (móvil, ordenador, televisión, domótica…), geolocalización
  aproximada del destino y detección de dominios de telemetría.
- **Flujos** (opcional) — captura pasiva con tshark: DNS, SNI de TLS, bytes y
  destinos geolocalizados.

## Dashboards provisionados

- `netviz-dns` — *Red doméstica: DNS, dispositivos y tráfico*. Un único dashboard
  con todo lo observado: resumen (consultas, % bloqueadas, equipos, sin DNS
  visible), tabla por dispositivo (consultas, bloqueos, telemetría), top de
  dominios externos/bloqueados/telemetría, series temporales de consultas y de
  tráfico capturado, geomapa de destinos DNS y tabla de flujos reales.
- Dashboards heredados: velocidad/conectividad y tráfico WAN del router.

## Componentes nativos de macOS (opcionales)

Docker Desktop no puede capturar la interfaz física ni emitir DHCP en la LAN, así
que estas dos piezas corren en el host:

```bash
# Captura de paquetes — sin sudo (grupo access_bpf)
python3 capture/sensor.py --iface en0
make install-capture            # persistente (LaunchAgent)

# Proxy DHCP — el router sigue repartiendo IPs, solo se anuncia AdGuard como DNS
make proxy                      # primer plano; mata instancias previas
make proxy-stop                 # para cualquier instancia
make install-dhcp-proxy         # persistente (LaunchDaemon, pide sudo)
```

En Linux la captura sí puede ir en contenedor: `docker compose --profile capture up -d`.

### Apagarlo todo (un solo comando)

Todo el ciclo de vida está en el Makefile; no hace falta recordar procesos sueltos:

```bash
make stop-all               # stack + sensor del Mac + sensor remoto + proxy DHCP + AdGuard
make stop-all KEEP=adguard  # lo mismo pero deja AdGuard resolviendo
make running                # qué queda vivo (contenedores, sensores, 9101, 53, web)
```

`stop-all` es tolerante: si un componente no está o el host remoto está apagado, sigue con el resto.
Lo que necesite `sudo` (proxy DHCP y AdGuard) avisa y se queda pendiente, sin bloquear la ejecución.


## Alcance y límites (importante)

- **DNS ≠ tráfico.** Se registra el dominio consultado y su respuesta, no cada
  conexión ni la ruta HTTPS. DoH/DoT y las conexiones a IP directa se escapan del
  DNS; la captura sí ve el SNI salvo en QUIC.
- **Geolocalización** — la posición es del endpoint público (CDN/anycast), no de
  tus equipos. Las IPs privadas no se geolocalizan.
- **Atribución por dispositivo** — exige que cada equipo use AdGuard como DNS; por
  eso existe el proxy DHCP. Sin él, AdGuard solo ve a quien apunte a él.
- **Un solo SSID por radio** — un Mac no puede estar en dos redes Wi-Fi a la vez;
  y estar en una red no da acceso al tráfico de otros clientes (WPA2/3).
- **Redes separadas** — si el router publica un segundo SSID en otra subred
  (`198.51.100.0/24` en este caso), esos equipos no pasan por el proxy del Mac.
- **El router** solo muestra telemetría agregada: no tiene port mirroring, SNMP
  cerrado, UPnP/IGD y TR-069 inaccesibles.

## Seguridad

- `router.env`, `adguard.env` y `.env` están ignorados por Git, con permisos `600`,
  y se montan como solo lectura.
- Ningún puerto se publica fuera de `127.0.0.1`; no expongas Prometheus ni Grafana
  a Internet.
- Retención de Prometheus configurable con `PROMETHEUS_RETENTION` (30 días por
  defecto).

## Problemas típicos

| Síntoma | Causa / solución |
| --- | --- |
| `dns-map` sin consultas y 401 en logs | credenciales de AdGuard incorrectas en `adguard.env` |
| Error de montaje con `adguard.env` | `make env` antes de `make up` (Docker crearía un directorio) |
| Dashboard sin datos por dispositivo | nadie usa AdGuard como DNS → activa el proxy DHCP |
| Grafana no arranca | falta `GRAFANA_ADMIN_PASSWORD` en `.env` |
| `router_exporter_scrape_success 0` | sesión del router caída o credenciales cambiadas |

## Estructura

```
dns-map/            colector DNS + mapa + API (Python stdlib, imagen propia)
router-exporter/    exporter del ZTE (inventario + contadores WAN)
contract-exporter/  compara velocidad medida con la contratada
capture/            sensor de paquetes con tshark + Dockerfile (Linux)
capture/windows/    instalación del sensor en un host Windows (Perdigon)
dhcp-proxy/         proxy DHCP con dnsmasq + LaunchDaemon
prometheus/ grafana/ alertmanager/ blackbox/ ping/   configuración del stack
```

## Host remoto (captura delegada)

La conexión a Perdigon **no vive en este repo**: está en `~/Repos/net-conn`, una
herramienta independiente y reutilizable por otros proyectos.

```bash
python3 ~/Repos/net-conn/remote.py status equipo
make remote-status                # atajo, usa NETCONN=$(HOME)/Repos/net-conn
```

### Sensor del puerto espejo, bajo demanda

El switch tiene espejado el puerto del **router**, así que ese sensor ve todo el
tráfico de la casa (salvo LAN↔LAN). Es la **fuente de verdad** de los dashboards.

La tarea en Perdigon **no arranca sola**; se levanta cuando hace falta:

```bash
make sensor-up        # arranca y comprueba /healthz
make sensor-status    # estado de la tarea + endpoint
make sensor-down      # la para
```

Variables: `H=equipo`, `SENSOR_HOST=192.0.2.46`, `SENSOR_TASK=netviz-capture`.

Instalación en ese equipo Windows:

```bash
python3 ~/Repos/net-conn/remote.py copy equipo capture/sensor.py netviz-capture/sensor.py
python3 ~/Repos/net-conn/remote.py copy equipo capture/cdn-map.json netviz-capture/cdn-map.json
python3 ~/Repos/net-conn/remote.py copy equipo capture/windows/install-capture-windows.ps1 netviz-capture/install.ps1
python3 ~/Repos/net-conn/remote.py run equipo "powershell -NoProfile -ExecutionPolicy Bypass -File netviz-capture\install.ps1 -Adapter Ethernet -Port 9101 -Lan 192.0.2.0/24"
```

`cdn-map.json` es opcional: nombra los flujos que llegan sin dominio (QUIC/HTTP-3)
con una tabla IP→etiqueta, sin tocar el pipeline ni reiniciar el sensor (ver
`capture/README.md`).

`make equipo` es la variante para hosts Linux/macOS (`systemd --user` o
LaunchAgent).
