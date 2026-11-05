# Tráfico del router ZTE ZXHN F6600P

## Hallazgos del firmware

En la interfaz de administración del F6600P, `Internet → Estatus → WAN`, la conexión activa `FTTH-Data` muestra contadores acumulados de bytes y paquetes recibidos/enviados. El exporter de este proyecto consulta el endpoint WAN del router y publica esos contadores en Prometheus.

Una consulta SNMP de solo lectura a UDP/161 con la comunidad pública habitual no obtuvo respuesta. Tampoco vimos una opción de SNMP ni de port mirroring en los menús revisados; esto no descarta funciones ocultas o dependientes del firmware del proveedor.

## Qué se mide

- **Velocidad contratada vs. medida:** prueba activa de Ookla desde el host Docker; no es lectura del tráfico del router.
- **Tráfico WAN agregado:** contadores `FTTH-Data` de bytes y paquetes. Prometheus calcula el caudal mediante `rate()` y Grafana lo muestra en *Tráfico WAN — ZTE F6600P*.
- **Tráfico por dispositivo/flujo:** no se obtiene de esos contadores WAN. Requiere SPAN/port mirroring o TAP y un sensor conectado al enlace; si el F6600P no lo ofrece, hace falta un switch gestionable o un gateway Linux/OpenWrt en el camino del tráfico.

## Credenciales

El exporter lee `ROUTER_USERNAME` y `ROUTER_PASSWORD` de `router.env`, excluido de Git y montado como solo lectura. Mantén ese archivo con permisos `600`; no pongas las claves en el repositorio, el Kanban ni los mensajes.

## Captura completa por paquetes

1. Verificar si router o switch puede duplicar el enlace WAN en ambas direcciones.
2. Conectar el puerto espejo/TAP a una interfaz dedicada en un host Linux o sensor.
3. Ejecutar Zeek u otra herramienta de análisis en esa interfaz. Un contenedor en una red bridge normal no ve el tráfico de otros equipos.
4. Docker Desktop en macOS no entrega automáticamente paquetes de una interfaz física a un contenedor; para captura completa suele ser preferible un host Linux físico o una VM con passthrough compatible.

## Prueba de velocidad

La stack realiza Ookla cada 30 minutos y compara bajada/subida con el contrato de `.env`. Consume tráfico y no debe confundirse con volumen mensual ni con captura de paquetes.
