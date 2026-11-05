# AGENTS.md — monitor_internet

Stack de observabilidad de la red doméstica: Prometheus, Grafana, Alertmanager,
dns-map (mapa Leaflet) y un sensor de captura. Las reglas generales de trabajo
están en la política global; aquí solo lo específico del repo.

## Comandos

| Comando | Qué hace |
|---|---|
| `make up` | Crea secretos desde `*.example` y levanta el stack |
| `make test` | Tests unitarios de `dns-map` y `capture` |
| `make verify` | **Gate de "hecho"**: tests + compose válido + endpoints vivos (`SKIP_LIVE=1` omite lo segundo) |
| `make doctor` | Diagnóstico de solo lectura (stack, proxy, sensor, AdGuard, dispositivos) |
| `make sensor-up` / `sensor-down` / `sensor-status` | Sensor tshark bajo demanda en `equipo` (sin disparador por diseño) |
| `make package` | Tar sin secretos |

## Hechos del entorno

- Puertos: Prometheus 9090, Alertmanager 9093, Grafana 3000, dns-map 8080, sensor 9101.
- Red: `192.0.2.0/24` (router ZTE 192.0.2.1) y `198.51.100.0/24` tras `SSID MI-RED-WIFI`.
  Switch TP-Link TL-SG108PE en `192.0.2.253`; espejo 4→2 (router→PC con `equipo`).
- El espejo del uplink solo ve tráfico de equipos **cableados**; no se puede afirmar nada
  sobre un cliente Wi-Fi del router.
- AdGuard Home es nativo (`/Applications/AdGuardHome`), DNS en :53 y API/web en :80 con
  basic auth; su `AdGuardHome.yaml` es 0600 root:wheel.
- El router solo expone API de estado: sin SNMP, UPnP, TR-069 ni mirroring propio.
- Hosts remotos vía `net-conn` (`$(NETCONN)/remote.py`), nunca con SSH a mano.

## Verificación

- `make verify` en verde antes de decir que algo funciona.
- Un endpoint se considera vivo solo si responde 200 con `curl`; los logs no bastan.
- Grafana: CARTO exige API key, usar teselas Esri XYZ en los geomap.

## Reglas

- Secretos en `.env`, `router.env`, `adguard.env` (0600, gitignored); nunca en el chat.
- No cambiar configuración de red o de filtrado sin presentar antes las opciones.
- Cambios de dashboard: auditar con `query_range`, no con instant queries.

## Decisiones

`DECISIONS.md` guarda las decisiones con sus alternativas y consecuencias. Antes de
revertir una, añade una entrada nueva fechada; no edites la antigua.
