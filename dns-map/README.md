# dns-map · mapa de dispositivos y conexiones

Servicio que convierte el registro de consultas de AdGuard Home en un mapa y en un
inventario tipado de la red doméstica.

## Qué hace

1. **Inventario** — lee `router-exporter:9800/metrics` (ZTE F6600P) y obtiene los
   equipos conectados: MAC, IP, hostname, banda/SSID o puerto LAN.
2. **Tipología** — clasifica cada equipo como `móvil`, `ordenador`, `televisión`,
   `domótica`, `impresora`, `cámara`, `aspirador`, `red`, … El firmware ZTE **no
   envía ningún campo de tipo**, así que la clasificación se infiere por:
   `device-overrides.csv` (manda) → hostname conocido → fabricante del OUI (IEEE).
3. **Consultas DNS** — sondea `GET /control/querylog` de AdGuard Home cada 60 s y
   guarda cada consulta con su cliente, dominio, tipo y la IP de destino.
4. **Geolocalización** — resuelve las IPs públicas de destino con `ip-api.com`
   (lote de 100, resultado cacheado en SQLite). Las IPs privadas se marcan como
   tráfico **interno** y no salen a Internet.
5. **Mapa** — `http://127.0.0.1:8080` con cuatro vistas: mapa mundial con arcos
   desde casa, topología de la red local, tabla de dispositivos y consultas recientes.

## Puesta en marcha

```bash
cd ~/Repos/monitor_internet
printf 'AGH_USER=%s\nAGH_PASS=%s\n' "$USER_ADGUARD" "$PASS_ADGUARD" > adguard.env
chmod 600 adguard.env
# AdGuard API debe responder 200 con esas credenciales:
curl -s -o /dev/null -w '%{http_code}\n' -u "$USER_ADGUARD:$PASS_ADGUARD" http://127.0.0.1/control/status
docker compose up -d dns-map
open http://127.0.0.1:8080
```

Comprobado en este equipo: AdGuard Home corre como root y sirve **DNS en :53** y la
**web/API en :80** (`/control/querylog` exige autenticación básica). Su
`AdGuardHome.yaml` es `0600 root:wheel`, así que no se puede leer sin `sudo`: si
hay que averiguar el puerto, se comprueba con `nc -vz 127.0.0.1 80` o `dig`, no
con `lsof` (los sockets de un proceso root no aparecen para un usuario normal).

Ojo: si `adguard.env` no existe antes de `docker compose up`, Docker crea un
**directorio** en su lugar y el montaje falla de forma confusa.

`adguard.env` y `router.env` son secretos locales (`0600`), montados como solo
lectura; no se copian a la imagen ni aparecen en logs ni en métricas.

## Grafana

El colector expone `/metrics` y Prometheus lo scrapea como job `netviz-dns`. El
dashboard **“Red doméstica: DNS, dispositivos y privacidad”** (uid `netviz-dns`)
se provisiona solo desde `grafana/dashboards/netviz-dns.json`:

- consultas totales, % bloqueadas, equipos conectados y **equipos sin DNS visible**;
- tablas de actividad y de telemetría por dispositivo;
- top de dominios de telemetría y de dominios externos/bloqueados;
- geomapa de destinos (coordenadas como campos `lat`/`lon`).

Métricas disponibles: `netviz_queries_total{kind}`, `netviz_devices{network}`,
`netviz_device_queries_total{device,type,network,ip}`,
`netviz_device_blocked_total`, `netviz_device_tracker_total`,
`netviz_device_silent`, `netviz_domain_queries_total{device,domain,kind,tracker}`
y `netviz_destination_total{lat,lon,city,country}`.

## Privacidad: qué se puede y qué no se puede afirmar

La pestaña **Privacidad** y los paneles equivalentes responden a “¿qué consulta mi
tele o mi lavadora?” solo si esos equipos hablan con AdGuard. Si no aparecen,
el panel los marca como **equipos sin DNS visible**: no prueba que no envíen nada,
prueba que no se puede ver desde DNS.

Barreras reales encontradas en esta instalación:

- **AdGuard debe escuchar en la LAN.** Si su `bind_hosts` apunta a una IP concreta
  y esa IP cambia (DHCP), el 53 deja de responder: `nc -vz <ip> 53` lo delata.
  Lo correcto es escuchar en todas las interfaces.
- **El router debe anunciar esa IP por DHCP.** En este ZTE el paquete DHCP sigue
  entregando `192.0.2.1`; hasta cambiarlo (si el firmware lo permite), AdGuard
  no recibe ni una consulta.
- **IPs y MACs cambian.** Con MAC privada rotatoria el router ve “equipos”
  distintos y con DHCP el mismo equipo cambia de IP: por eso la identidad se
  congela en el momento de ingerir la consulta (`client_mac`, `client_name`) y no
  se deduce después por IP.
- **DNS cifrado y DNS propio se escapan.** DoH/DoT y resolutores embebidos en la
  tele o la lavadora no pasan por AdGuard: para auditarlos hace falta captura de
  flujos (espejo/mirror), no DNS.


- **DNS ≠ tráfico.** Se registra el dominio consultado y su respuesta, no cada
  conexión ni la ruta HTTPS. DoH/DoT y conexiones a IP directa se escapan.
- **La geolocalización es del endpoint público** (CDN, DNS anycast), no de la
  ubicación física de tus equipos: verás muchos puntos en Frankfurt, Dublín o
  Ámsterdam aunque navegues desde España.
- **Atribución por dispositivo** solo es correcta si cada equipo usa AdGuard como
  DNS (DHCP con DNS = IP del Mac). Si un dispositivo usa su propio DNS, no aparece.
- El histórico lo guarda este servicio (SQLite, volumen `dns_map_data`), porque el
  query log de AdGuard es en memoria y rota.

## Endpoints

| Ruta | Contenido |
| --- | --- |
| `/api/summary` | totales, tipos de tráfico, países, dominio de origen |
| `/api/map?device=<ip>&hours=168` | puntos geolocalizados con arcos y dominios top |
| `/api/devices` | inventario tipado con nº de consultas |
| `/api/internal` | destinos internos y quién los consulta |
| `/api/recent?limit=300` | últimas consultas |

## Variables de entorno

| Variable | Por defecto | Uso |
| --- | --- | --- |
| `ADGUARD_URL` | `http://host.docker.internal:80` | API de AdGuard Home |
| `ROUTER_EXPORTER_URL` | `http://router-exporter:9800/metrics` | inventario |
| `POLL_SECONDS` | `60` | frecuencia de sondeo |
| `GEOIP_API` | `ip-api` | `off` para no enviar IPs a terceros |
| `HOME_FILE` | `/data/home.json` | coordenadas de casa (`{"lat":..,"lon":..}`) |
