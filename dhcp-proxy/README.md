# dhcp-proxy · anunciar AdGuard como DNS sin tocar el DHCP del router

El router ZTE sigue repartiendo direcciones; `dnsmasq` solo escucha sus
respuestas y reescribe la opción 6 (DNS) para apuntar a AdGuard en este Mac.

- **No hay pool propio** → no puede haber IP duplicada.
- **El router sigue siendo el DHCP** → si el Mac se apaga, los equipos renuevan igual.
- Solo afecta a **192.0.2.0/24**; los equipos de `198.51.100.0/24` (segundo SSID) siguen como están.
- Necesita `dnsmasq` (instalado con Homebrew) y root para el puerto 67.

## Requisito previo importante

El proxy anuncia **la IP actual del Mac**. Si esa IP cambia, los equipos dejan de
resolver hasta que el proxy se reinicie (el supervisor lo hace en ~30 s, pero
durante ese rato se nota). Para que sea estable, antes o después conviene:

1. en el Mac: Ajustes → Wi‑Fi → tu red → **Dirección Wi‑Fi privada: desactivada**;
2. en el router: **reserva DHCP** para ese MAC, por ejemplo `192.0.2.10`.

## Por qué puede no funcionar (comprobado en esta red)

El proxy **sí recibe** los DHCPDISCOVER (aparecen en el log como
`available DHCP subnet: 192.0.2.0/255.255.255.0`), pero **no puede inyectar
nada**. Motivo: el router entrega su OFFER/ACK en *unicast* a la MAC del cliente,
y en Wi-Fi el adaptador del Mac no puede leer tramas dirigidas a otra estación
(cifrado por cliente + reenvío del AP). Sin ver la respuesta del servidor, dnsmasq
no tiene nada que reescribir.

Consecuencia práctica: este mecanismo solo funciona si el Mac comparte el mismo
segmento físico y ve ese unicast (cable con hub/switch sin aislamiento, o el Mac
como puente). En una LAN Wi-Fi normal **no sirve**.

Alternativa cuando el DHCP del router no se puede tocar: configurar el DNS a mano
en el propio dispositivo (ajustes de red → DNS manual → IP del Mac). Funciona en
televisores, consolas y muchos electrodomésticos conectados.

## Prueba rápida (sin instalar servicio)

```bash
sudo /Users/usuario/Repos/monitor_internet/dhcp-proxy/run-proxy.sh en0
```

Deja el terminal abierto y, en otra ventana:

```bash
tail -f /tmp/netviz-dhcp-proxy.log
```

Cuando un equipo renueve (apagar/encender Wi‑Fi en la tele, por ejemplo) verás su
DHCPREQUEST y la respuesta con la opción DNS inyectada. Aparecerá además como
cliente en `http://127.0.0.1:8080` (pestaña Privacidad). Ctrl‑C para parar.

## Servicio permanente

```bash
sudo cp /Users/usuario/Repos/monitor_internet/dhcp-proxy/com.usuario.dhcp-proxy.plist /Library/LaunchDaemons/
sudo chown root:wheel /Library/LaunchDaemons/com.usuario.dhcp-proxy.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/com.usuario.dhcp-proxy.plist
```

Comprobar y parar:

```bash
sudo launchctl print system/com.usuario.dhcp-proxy | grep -E 'state|pid'
sudo launchctl bootout system /Library/LaunchDaemons/com.usuario.dhcp-proxy.plist
```

## Cómo saber si funciona

1. `tail -f /tmp/netviz-dhcp-proxy.log` muestra las concesiones atendidas.
2. En el equipo de prueba: Apagado/encendido de Wi‑Fi y luego
   `ipconfig getpacket en0 | grep domain_name_server` debe devolver la IP del Mac.
3. En el dashboard **Red doméstica: DNS, dispositivos y privacidad**, el equipo
   deja de estar en “sin DNS visible” y empiezan a contar sus consultas.

## Reversión

```bash
sudo launchctl bootout system /Library/LaunchDaemons/com.usuario.dhcp-proxy.plist
```

Los equipos vuelven al DNS del router en su siguiente renovación (lease de 24 h);
nada queda escrito en ellos.
