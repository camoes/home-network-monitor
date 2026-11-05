SHELL := /bin/bash
COMPOSE := docker compose
SECRETS := router.env adguard.env
H ?= equipo
IFACE ?= eth0
NETCONN ?= $(HOME)/Repos/net-conn

.DEFAULT_GOAL := help

help: ## Muestra esta ayuda
	@echo "Stack de monitorización doméstica"
	@echo
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'
	@echo
	@echo "Primeros pasos:  make env && edit .env && make up"

env: ## Crea .env y los ficheros de secretos a partir de los *.example
	@test -f .env || (cp .env.example .env && echo "creado .env (edita GRAFANA_ADMIN_PASSWORD)")
	@test -f router.env || (cp router.env.example router.env && chmod 600 router.env && echo "creado router.env (rellena las credenciales del router)")
	@test -f adguard.env || (cp adguard.env.example adguard.env && chmod 600 adguard.env && echo "creado adguard.env (rellena las credenciales de AdGuard)")
	@test -f device-overrides.csv || (echo "mac,name,device_type" > device-overrides.csv && echo "creado device-overrides.csv")
	@chmod 600 router.env adguard.env 2>/dev/null || true

up: env ## Levanta todo el stack (build incluido)
	$(COMPOSE) up -d --build
	@$(MAKE) --no-print-directory status

down: ## Para y elimina los contenedores (conserva los volúmenes)
	$(COMPOSE) down --remove-orphans

restart: ## Reinicia el stack sin reconstruir
	$(COMPOSE) restart

ps: ## Estado de los contenedores
	$(COMPOSE) ps

logs: ## Logs en vivo (make logs S=grafana para uno solo)
	$(COMPOSE) logs -f --tail=120 $(S)

test: ## Tests unitarios de dns-map y capture
	cd dns-map && python3 -m unittest test_netviz
	cd capture && /usr/bin/python3 -m unittest test_sensor

verify: ## Gate de hecho: tests, compose válido y endpoints vivos (SKIP_LIVE=1 omite lo último)
	@$(MAKE) --no-print-directory test
	@$(COMPOSE) config -q && echo "  ✓ compose válido"
	@if [ -n "$(SKIP_LIVE)" ]; then echo "  · endpoints omitidos (SKIP_LIVE=1)"; else $(MAKE) --no-print-directory verify-live; fi
	@echo "verify: OK"

verify-live: ## Comprueba que cada endpoint responde 200 (falla si alguno no)
	@fail=0; for url in http://127.0.0.1:9090/-/healthy http://127.0.0.1:9093/-/healthy \
	            http://127.0.0.1:3000/api/health http://127.0.0.1:8080/healthz ; do \
	  code=$$(curl -s -o /dev/null -m 3 -w '%{http_code}' $$url || true); \
	  if [ "$$code" = "200" ]; then printf "  ✓ %s\n" "$$url"; \
	  else printf "  ✗ %s (%s)\n" "$$url" "$${code:-sin respuesta}"; fail=1; fi; \
	done; exit $$fail

status: ## Salud de los servicios y URLs
	@echo "== contenedores =="
	@$(COMPOSE) ps
	@echo
	@echo "== endpoints =="
	@for url in http://127.0.0.1:9090/-/healthy http://127.0.0.1:9093/-/healthy \
	            http://127.0.0.1:3000/api/health http://127.0.0.1:8080/healthz \
	            http://127.0.0.1:9101/healthz ; do \
	  code=$$(curl -s -o /dev/null -m 3 -w '%{http_code}' $$url || true); \
	  printf "  %-42s %s\n" "$$url" "$${code:-sin respuesta}"; \
	done

reload: ## Recarga la configuración de Prometheus sin reiniciar
	@curl -s -o /dev/null -w 'prometheus reload: %{http_code}\n' -X POST http://127.0.0.1:9090/-/reload

install-capture: ## (macOS) Instala el sensor de captura como LaunchAgent
	-launchctl bootout gui/$$(id -u)/com.usuario.netviz-capture 2>/dev/null || true
	launchctl bootstrap gui/$$(id -u) ~/Library/LaunchAgents/com.usuario.netviz-capture.plist
	@launchctl print gui/$$(id -u)/com.usuario.netviz-capture | grep -E 'state|pid' || true

uninstall-capture: ## (macOS) Desinstala el sensor de captura
	-launchctl bootout gui/$$(id -u)/com.usuario.netviz-capture

proxy: ## (macOS, sudo) Arranca el proxy DHCP en primer plano (mata duplicados)
	-sudo pkill -f "dnsmasq -C /tmp/netviz-dhcp-proxy.conf" 2>/dev/null || true
	sudo dhcp-proxy/run-proxy.sh en0

proxy-stop: ## (macOS, sudo) Para cualquier proxy DHCP en marcha
	-sudo pkill -f "dnsmasq -C /tmp/netviz-dhcp-proxy.conf" 2>/dev/null || true

install-dhcp-proxy: ## (macOS, sudo) Instala el proxy DHCP como LaunchDaemon
	-sudo pkill -f "dnsmasq -C /tmp/netviz-dhcp-proxy.conf" 2>/dev/null || true
	-sudo launchctl bootout system /Library/LaunchDaemons/com.usuario.dhcp-proxy.plist 2>/dev/null || true
	sudo cp dhcp-proxy/com.usuario.dhcp-proxy.plist /Library/LaunchDaemons/
	sudo chown root:wheel /Library/LaunchDaemons/com.usuario.dhcp-proxy.plist
	sudo launchctl bootstrap system /Library/LaunchDaemons/com.usuario.dhcp-proxy.plist
	@sudo launchctl print system/com.usuario.dhcp-proxy | grep -E 'state|pid' || true

uninstall-dhcp-proxy: ## (macOS, sudo) Desinstala el proxy DHCP
	-sudo launchctl bootout system /Library/LaunchDaemons/com.usuario.dhcp-proxy.plist 2>/dev/null || true
	-sudo pkill -f "dnsmasq -C /tmp/netviz-dhcp-proxy.conf" 2>/dev/null || true

bootstrap: ## Despliegue completo de una vez: entorno, stack, captura y proxy
	$(MAKE) --no-print-directory env
	$(MAKE) --no-print-directory up
	$(MAKE) --no-print-directory install-capture
	$(MAKE) --no-print-directory install-dhcp-proxy
	$(MAKE) --no-print-directory doctor

doctor: ## Diagnóstico completo (stack, proxy, sensor, AdGuard, dispositivos)
	@bash scripts/doctor.sh

dhcp-probe: ## (macOS, sudo) Prueba activa del proxy: DISCOVER real y DNS inyectado
	sudo python3 scripts/dhcp-probe.py --port 68

wol: ## Enciende un host por Wake-on-LAN (H=equipo)
	python3 $(NETCONN)/remote.py wake $(H)

remote-status: ## Estado de un host remoto (H=equipo)
	@python3 $(NETCONN)/remote.py status $(H)

remote-ensure: ## Enciende si hace falta y espera SSH (H=equipo)
	python3 $(NETCONN)/remote.py ensure $(H)

remote-ssh: ## Abre sesión SSH en el host (H=equipo)
	python3 $(NETCONN)/remote.py ssh $(H)

equipo: ## Instala el sensor de captura en el host (H=equipo IFACE=eth0)
	python3 $(NETCONN)/remote.py run $(H) "mkdir -p netviz-capture"
	python3 $(NETCONN)/remote.py copy $(H) capture/sensor.py netviz-capture/sensor.py
	python3 $(NETCONN)/remote.py copy $(H) capture/cdn-map.json netviz-capture/cdn-map.json
	python3 $(NETCONN)/remote.py copy $(H) capture/windows/install-capture-remote.sh netviz-capture/install.sh
	python3 $(NETCONN)/remote.py run $(H) "bash netviz-capture/install.sh $(IFACE)"

SENSOR_HOST ?= 192.0.2.46
SENSOR_TASK ?= netviz-capture

sensor-up: ## Arranca el sensor del puerto espejo (H=equipo) bajo demanda
	@python3 $(NETCONN)/remote.py task $(H) start $(SENSOR_TASK) 2>/dev/null
	@sleep 5
	@curl -s -m 5 http://$(SENSOR_HOST):9101/healthz | tee /dev/stderr | grep -q running \
	  && echo "sensor arriba" || (echo "el sensor no responde" && false)

sensor-down: ## Para el sensor del puerto espejo
	@python3 $(NETCONN)/remote.py task $(H) stop $(SENSOR_TASK) 2>/dev/null
	@echo "sensor parado"

sensor-status: ## Estado del sensor (proceso y endpoint)
	@python3 $(NETCONN)/remote.py task $(H) state $(SENSOR_TASK) 2>/dev/null || true
	@curl -s -m 4 http://$(SENSOR_HOST):9101/healthz || echo "  sin respuesta en $(SENSOR_HOST):9101"

renew-dhcp: ## (macOS, sudo) Renueva la IP del Mac y muestra el DNS recibido
	@echo "Aviso: la conexión puede caer unos segundos."
	sudo ipconfig set en0 DHCP
	@sleep 3
	@ipconfig getpacket en0 2>/dev/null | grep -A2 domain_name_server || echo "sin concesión nueva"

clean: ## Borra contenedores Y volúmenes (pierde histórico)
	@read -p "Esto borra Prometheus, Grafana y la base de dns-map. ¿Seguro? [s/N] " ans; \
	if [[ "$$ans" == "s" || "$$ans" == "S" ]]; then $(COMPOSE) down -v --remove-orphans; else echo "cancelado"; fi

package: ## Crea dist/monitor-internet-<fecha>.tar.gz sin secretos
	@mkdir -p dist
	@tar --exclude='./.git' --exclude='./dist' --exclude='./.env' \
	     --exclude='./router.env' --exclude='./adguard.env' \
	     --exclude='./dns-map-data' --exclude='./capture/devices.json' \
	     --exclude='./device-overrides.csv' --exclude='./.aider*' \
	     --exclude='*.bak' \
	     --exclude='*.pcapng' --exclude='__pycache__' \
	     -czf dist/monitor-internet-$$(date +%Y%m%d).tar.gz .
	@ls -lh dist/monitor-internet-$$(date +%Y%m%d).tar.gz | awk '{print "  ", $$NF, $$5}'

# --------------------------------------------------------------------- parar
# Un solo sitio para apagarlo todo: stack, sensores (Mac y remoto), proxy DHCP y
# AdGuard Home. Todo tolerante a fallos: si algo no está, sigue con lo demás.
ADGUARD_DIR ?= /Applications/AdGuardHome
KEEP ?=

stop-all: ## Para TODO el proyecto (stack, sensores, proxy, AdGuard). KEEP=adguard lo respeta
	@echo "== stack docker"; $(COMPOSE) down --remove-orphans 2>/dev/null || true
	@echo "== sensor del Mac"; launchctl bootout gui/$$(id -u)/com.usuario.netviz-capture 2>/dev/null || true; pkill -f 'capture/sensor.py' 2>/dev/null || true; echo "   ok"
	@echo "== sensor del puerto espejo"; python3 $(NETCONN)/remote.py task $(H) stop $(SENSOR_TASK) 2>/dev/null || echo "   host apagado o inalcanzable: nada que parar"
	@echo "== proxy DHCP"; sudo -n pkill -f "dnsmasq -C /tmp/netviz-dhcp-proxy.conf" 2>/dev/null && echo "   parado" || echo "   pendiente de sudo: sudo pkill -f 'dnsmasq -C /tmp/netviz-dhcp-proxy.conf'"
	@if [ "$(KEEP)" = "adguard" ]; then \
	   echo "== AdGuard Home: se deja como está (KEEP=adguard)"; \
	 else \
	   echo "== AdGuard Home"; \
	   sudo -n $(ADGUARD_DIR)/AdGuardHome -s stop 2>/dev/null && echo "   parado" || echo "   pendiente de sudo: sudo $(ADGUARD_DIR)/AdGuardHome -s stop"; \
	 fi
	@echo
	@echo "listo. Comprueba con: make running"

running: ## Qué queda vivo: contenedores, sensores, proxy, AdGuard
	@echo "contenedores:   $$(docker ps -q 2>/dev/null | wc -l | tr -d ' ') arriba"
	@echo "sensor local:   $$(pgrep -f 'capture/sensor.py' >/dev/null && echo 'corriendo' || echo 'parado')"
	@echo "puerto 9101:    $$(nc -z -w 1 127.0.0.1 9101 2>/dev/null && echo 'escuchando (Mac)' || echo 'libre (Mac)')"
	@echo "sensor remoto:  $$(curl -s -m 2 http://$(SENSOR_HOST):9101/healthz >/dev/null 2>&1 && echo 'responde' || echo 'sin respuesta')"
	@echo "proxy DHCP:     $$(pgrep -f 'netviz-dhcp-proxy' >/dev/null && echo 'corriendo' || echo 'parado')"
	@echo "AdGuard 53:     $$(nc -z -w 1 127.0.0.1 53 2>/dev/null && echo 'escuchando' || echo 'parado')"
	@echo "AdGuard web:    $$(curl -s -o /dev/null -w '%{http_code}' -m 2 http://127.0.0.1/ 2>/dev/null | grep -q 302 && echo 'responde' || echo 'parado')"


.PHONY: help env up down restart ps logs test verify verify-live status reload proxy proxy-stop install-capture uninstall-capture install-dhcp-proxy uninstall-dhcp-proxy bootstrap doctor dhcp-probe renew-dhcp wol remote-status remote-ensure remote-ssh equipo sensor-up sensor-down sensor-status package clean stop-all running
