# capture · sensor de paquetes

Captura pasiva con `tshark` en una interfaz del Mac y expone los flujos en
`127.0.0.1:9101/metrics` para Prometheus.

## Alcance real (importante)

Este sensor ve **solo el tráfico de este Mac**: lo que el equipo envía y recibe.
No ve la tele, la lavadora ni el móvil, porque en Wi-Fi el switch del router no
entrega su tráfico a este equipo. Para ver otros dispositivos hace falta una de
estas tres cosas, y ninguna está disponible en un F6600P de operador:

1. puerto espejo (SPAN) en el router/switch hacia este Mac;
2. el Mac como puerta de enlace de la LAN (rompe el enrutado normal);
3. un sensor Linux intercalado (router propio o AP con mirror).

Lo que sí aporta ya: dominios por SNI/DNS del propio Mac, bytes por destino,
geolocalización aproximada y detección de telemetría en el equipo que ejecuta
AdGuard.

## Permisos

`tshark` necesita acceso a `/dev/bpf*`. Este equipo ya tiene el grupo
`access_bpf` (lo instala Wireshark), así que **no hace falta sudo**:

```bash
id -Gn | tr ' ' '\n' | grep access_bpf   # debe imprimir access_bpf
```

## Uso manual

```bash
/usr/bin/python3 capture/sensor.py --iface en0
curl -s http://127.0.0.1:9101/metrics | head
```

Modo replay para depurar sin capturar:

```bash
/usr/bin/python3 capture/sensor.py --replay capture/sample.txt --port 9102
```

## Servicio permanente (una sola vez, en tu Terminal)

```bash
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.usuario.netviz-capture.plist
launchctl print gui/$(id -u)/com.usuario.netviz-capture | grep -E 'state|pid'
```

Para pararlo:

```bash
launchctl bootout gui/$(id -u)/com.usuario.netviz-capture
```

Logs en `/tmp/netviz-capture.log` y `/tmp/netviz-capture.err`.

## Métricas

| Métrica | Etiquetas | Significado |
| --- | --- | --- |
| `netviz_capture_up` | – | 1 si tshark está capturando |
| `netviz_capture_packets_total` | – | paquetes vistos |
| `netviz_capture_bytes_total` | – | bytes vistos |
| `netviz_capture_dns_packets_total` | – | paquetes DNS |
| `netviz_capture_sni_packets_total` | – | ClientHello con SNI |
| `netviz_flow_bytes_total` | `dst, domain, proto[, cdn]` | bytes por flujo |
| `netviz_flow_packets_total` | `dst, domain, proto[, cdn]` | paquetes por flujo |
| `netviz_client_bytes_total` | `client, name, type, dst, domain, proto[, cdn]` | bytes por equipo de la LAN |
| `netviz_cdn_named_bytes_total` | `cdn` | bytes nombrados por la tabla IP→CDN |
| `netviz_cdn_named_packets_total` | `cdn` | paquetes nombrados por la tabla IP→CDN |
| `netviz_domain_bytes_total` | `domain` | bytes por dominio |
| `netviz_domain_packets_total` | `domain` | paquetes por dominio |
| `netviz_capture_destination_bytes_total` | `dst, lat, lon, city, country` | bytes por destino con geolocalización |

Se mantienen las 200 series más pesadas de cada métrica para que la cardinalidad
no crezca sin control. La etiqueta `proto` es `servicio/dirección` y el servicio
se deduce del puerto **y del transporte** (`ip.proto`): un flujo por UDP al 443
sale como `quic/out` en lugar de `https/out`, así que «QUIC» se sostiene con el
dato, no con una suposición.

## Nombres IP→dominio: `peers.json`

El sensor aprende `IP del destino -> dominio` de los nombres que **ve en la
conexión** (SNI de TLS o cabecera `Host`) y los reutiliza para los paquetes de
respuesta y para los flujos que no traen nombre. Ese mapa se guarda en
`STATE_DIR/peers.json` (por defecto `~/.netviz-capture/peers.json`, o
`NETVIZ_CAPTURE_STATE`; ruta alternativa con `--peers RUTA`):

```json
{"version": 1, "ttl_seconds": 129600,
 "peers": {"142.251.151.4": {"domain": "www.youtube.com", "ts": 1793467227.0}}}
```

- **Sobrevive a los reinicios**: al arrancar se carga antes de capturar, así que
  un flujo que se quedó sin SNI (QUIC, conexión ya establecida) sigue atribuido en
  lugar de volver a `domain=""`. Se vuelca cada ~30 s desde `maintenance_loop`
  (escritura atómica: `.tmp` + `os.replace`) y al terminar un `--replay`.
- **Caduca**: `ts` es cuándo se observó el nombre por última vez. Pasadas 36 h
  (`--peers-ttl-h` o `NETVIZ_PEERS_TTL_H`; el rango razonable es 24-48 h) la
  entrada se descarta, para no etiquetar IPs de CDN recicladas con el inquilino
  anterior. Tope de 5 000 entradas, se van las más antiguas.
- **Las consultas DNS no bautizan al servidor**: un paquete DNS nombra lo que se
  pregunta, no el destino que responde, así que nunca alimenta el mapa y su flujo
  se publica sin dominio (`dst="8.8.8.8",domain="",proto="dns/out"`). Si una
  versión anterior dejó una entrada con ese patrón (`8.8.8.8 -> nrdp.logs...`),
  se borra al volver a ver la misma consulta. Los paquetes DNS siguen contando en
  `netviz_capture_dns_packets_total` y el nombre consultado sigue sumando sus
  bytes en `netviz_domain_bytes_total`.
- **Estado**: `/healthz` expone `peers: {learned, file, ttl_hours}`.
- **Borrar el fichero** olvida todos los nombres; no hace falta reiniciar (se
  reescribe con lo que se vaya aprendiendo).

## Respaldo por IP: nombrar flujos sin dominio (`cdn-map.json`)

Un flujo HTTP/3-QUIC o una conexión ya establecida llega **sin SNI**: el sensor
no puede leer el dominio y la serie sale con `domain=""`. Para esos casos hay una
tabla editable IP (o prefijo) → etiqueta que **sólo actúa como respaldo**:

- si el flujo trae SNI/Host/DNS, el dominio manda y la tabla no se aplica;
- sin tabla, el comportamiento es exactamente el de antes (sin etiqueta nueva);
- la etiqueta se publica en un label aparte, `cdn`, nunca dentro de `domain`.

Fichero (junto a `sensor.py`; ruta alternativa con `--cdn RUTA` o
`NETVIZ_CDN_FILE`):

```json
{
  "enabled": true,
  "debug": false,
  "prefixes": {
    "212.166.133.0/24": "CDN vídeo Google (googlevideo) – caché en Vodafone",
    "212.166.128.0/18": "CDN Vodafone AS12430 – sin SNI"
  }
}
```

La etiqueta es una **inferencia**, no un dominio observado: se elige con `whois`/RDAP
(ASN y `netname` del rango) y, cuando se puede, con una sonda TLS sin SNI al destino
(`openssl s_client -connect IP:443` sin `-servername`), que devuelve el certificado
por defecto y delata al CDN real. Ese es el caso de `212.166.133.0/24`:
`CN=*.googlevideo.com` (Google Trust Services) en `.207` y `.210`, es decir caché de
Google **alojada** en Vodafone, no «CDN Vodafone»; por eso ese /24 lleva la etiqueta
concreta y el resto del /18 una genérica de operador.

- **Ganar la coincidencia más específica**: se ordena por longitud de prefijo.
- **Recarga en caliente**: se relee si cambia el `mtime` (cada ~30 s), sin reiniciar.
- **Desactivar** (tres formas, todas reversibles): `"enabled": false` en el JSON,
  borrar/renombrar el fichero, o arrancar con `--no-cdn`.
- **Depurar**: `NETVIZ_CDN_DEBUG=1` imprime una línea por destino novedoso
  (`cdn: 212.166.133.207 sin dominio -> '…' (cliente 192.0.2.64)`) y
  `/healthz` expone `cdn: {enabled, prefixes, file, debug, named_packets}`.

Cómo elegir la etiqueta: `whois`/RDAP del destino (`netname`, `origin` ASN) dicen
de quién es el rango; la etiqueta es una **inferencia**, no un dominio observado.

## Limitaciones conocidas

- **QUIC/HTTP3**: el SNI no se puede leer de un flujo QUIC ya establecido, así que
  esos flujos aparecen con dominio vacío y `proto="quic/…"`; sólo se nombran si el
  SNI del handshake se capturó (entonces el nombre queda en `peers.json`) o si su
  destino cae en `cdn-map.json` (label `cdn`).
- **DoH**: si una aplicación resuelve por HTTPS, el DNS no se ve, pero el SNI del
  destino TLS sí (salvo QUIC).
- **Solo IPv4/IPv6 unicast**: broadcasts y multicast se descartan al agregar.
- Los contadores viven en memoria: al reiniciar el sensor, Prometheus ve un
  reinicio de contador (lo detecta solo, `rate()` lo maneja). El mapa
  IP→dominio es la excepción: se persiste en `peers.json`.
