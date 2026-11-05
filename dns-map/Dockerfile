FROM python:3.12-alpine

# CA bundle is required to download the IEEE OUI list and query ip-api over HTTPS.
RUN apk add --no-cache ca-certificates

WORKDIR /app
CMD ["python", "/app/collector.py"]
