# DECISIONS.md — monitor_internet

Registro de decisiones con alternativas reales. Formato: contexto, decisión,
consecuencias. No se reescribe el pasado: una decisión se supera con una entrada
nueva fechada más arriba.

> Las entradas anteriores al 2026-11-01 están reconstruidas de la memoria del
> proyecto; la fecha es aproximada.

## 2026-11-01 — Gate `make verify`

**Contexto**: el "hecho" dependía de mi disciplina, y `make doctor` imprime ✗ pero
siempre sale con código 0, así que no sirve como gate.
**Decisión**: `make verify` = tests de `dns-map` y `capture` + `compose config -q` +
cada endpoint en 200. `SKIP_LIVE=1` omite la parte de endpoints para ejecuciones sin stack.
**Alternativas**: usar `doctor` como gate (descartado: nunca falla); CI en la nube
(descartado por ahora: el stack es local).
**Consecuencias**: con el stack parado el gate falla — comprobado. `doctor` sigue
existiendo para diagnóstico legible.

## 2026-10 (aprox.) — Sensor de captura bajo demanda, sin disparador

**Contexto**: el sensor tshark corre en `equipo` sobre el puerto espejo.
**Decisión**: no se deja siempre encendido ni con disparador; se arranca con
`make sensor-up` y se para con `make sensor-down`.
**Consecuencias**: no hay captura continua; el histórico depende de cuándo se arranca.
El puerto 9101 solo responde mientras está activo (por eso queda fuera de `verify-live`).

## 2026-10 (aprox.) — Teselas Esri XYZ en los geomap de Grafana

**Contexto**: CARTO pasó a exigir API key y los paneles quedaron sin mapa base.
**Decisión**: `World_Dark_Gray_Base` + `World_Dark_Gray_Reference` de Esri, con la
capa de referencia superpuesta a opacidad 0.9 para que se lean fronteras y etiquetas.
**Alternativas**: registrar una cuenta CARTO (descartado: clave y cuota para un panel local).
**Consecuencias**: sin clave ni coste; dependemos de las teselas públicas de Esri.

## 2026-10 (aprox.) — AdGuard Home nativo, fuera del compose

**Contexto**: se necesitaba DNS en :53 y su UI/API en :80 dentro de la LAN.
**Decisión**: instalar AdGuard Home nativo en `/Applications/AdGuardHome`.
**Consecuencias**: su `AdGuardHome.yaml` es 0600 root:wheel y no se versiona; el ciclo
de vida del DNS no lo gestiona Docker, así que `make up/down` no lo afecta.

## 2026-10 (aprox.) — Espejo 4→2 en el switch TP-Link TL-SG108PE

**Contexto**: el router ZTE no ofrece mirroring, SNMP ni TR-069; se quería ver el
tráfico de los equipos.
**Decisión**: espejo del puerto del router (4) al del PC sensor (2).
**Alternativas**: capturar en el propio Mac (descartado: solo vería su propio tráfico).
**Consecuencias**: solo se ve el tráfico de equipos **cableados**; el Wi-Fi de los
clientes del router no cruza ese puerto, así que no se puede afirmar nada sobre un
aparato inalámbrico a partir de esta captura.
