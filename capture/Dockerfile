FROM python:3.12-alpine

# tshark aporta el parser de protocolos; ca-certificates, la geolocalización.
RUN apk add --no-cache tshark ca-certificates

WORKDIR /app
COPY sensor.py /app/sensor.py
# Tabla IP->etiqueta para flujos sin dominio (opcional, se puede montar encima)
COPY cdn-map.json /app/cdn-map.json

ENV NETVIZ_TSHARK=/usr/bin/tshark \
    NETVIZ_CAPTURE_STATE=/state \
    NETVIZ_CAPTURE_PORT=9101

CMD ["python", "-u", "/app/sensor.py"]
