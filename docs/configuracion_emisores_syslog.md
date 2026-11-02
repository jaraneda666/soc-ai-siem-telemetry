# Guía de Configuración: Reenvío Syslog Centralizado (RFC 5424)

Esta guía detalla los comandos y procedimientos necesarios para configurar todos los dispositivos de la red local para que reenvíen sus registros de eventos al colector central Vector en el NAS Synology (`192.168.1.100:514`).

---

## 1. Configuración en Router Principal OpenWrt (192.168.1.1)

Accede al router vía SSH:

```bash
ssh root@192.168.1.1
```

Aplica la configuración declarativa UCI para activar el reenvío remoto de Syslog:

```bash
# Definir IP y puerto de destino del colector Vector
uci set system.@system[0].log_ip='192.168.1.100'
uci set system.@system[0].log_port='514'
uci set system.@system[0].log_proto='udp'

# Confirmar y reiniciar el servicio de logging
uci commit system
/etc/init.d/log restart
```

### Verificación de Registro de Cortafuegos WAN
Para asegurar que los paquetes no autorizados en la interfaz WAN se registren y lleguen a Vector, valida que la zona `wan` en `/etc/config/firewall` tenga activo el registro:

```bash
uci set firewall.@zone[1].log='1'
uci set firewall.@zone[1].log_limit='60/minute'
uci commit firewall
/etc/init.d/firewall reload
```

---

## 2. Configuración en Access Points UniFi con OpenWrt

Ejecuta el mismo procedimiento en ambos puntos de acceso (`192.168.1.253` y `192.168.1.254`):

```bash
ssh root@192.168.1.253
uci set system.@system[0].log_ip='192.168.1.100'
uci set system.@system[0].log_port='514'
uci set system.@system[0].log_proto='udp'
uci commit system
/etc/init.d/log restart
```

Esto enviará eventos de asociación Wi-Fi, autenticación de clientes y cambios en las VLANs 50, 60 y 70.

---

## 3. Configuración en Switch UniFi US-8-60W

Desde la interfaz web de UniFi Network Controller o mediante la consola de gestión CLI:

1. Ve a **Settings > System > Advanced > Remote Logging**.
2. Habilita **Syslog** y marca:
   - *Device Logs* (Registros del sistema y enlaces de puertos).
   - *Client Logs* (Eventos de conexión de clientes por cable).
3. Ingresa la dirección IP del servidor Syslog: `192.168.1.100` en el puerto `514`.
4. Aplica los cambios para aprovisionar el conmutador.

---

## 4. Configuración de Logs Locales en Synology DSM

Para que el propio NAS envíe sus eventos de autenticación y proxy inverso a Vector:

1. Ingresa a **DSM > Centro de Registros > Registro de Historial**.
2. En la pestaña **Reenvío de Registros**, marca *Reenviar registros a un servidor syslog*:
   - **Servidor:** `127.0.0.1` o `192.168.1.100`
   - **Puerto:** `514`
   - **Protocolo de transferencia:** `UDP`
   - **Formato de registro:** `RFC 5424` (IETF)
3. Selecciona las categorías que deseas auditar: *Sistema, Conexión, Nginx/Web*.
4. Guarda la configuración y presiona **Enviar registro de prueba**.

---

## 5. Prueba de Recepción y Simulación de Evento de Seguridad

Puedes comprobar que el colector Vector está procesando y entregando registros a Grafana Loki y al Conector IA ejecutando una inyección manual desde cualquier estación de trabajo en la LAN:

### Envío de Registro de Prueba desde PowerShell:

```powershell
$udpClient = New-Object System.Net.Sockets.UdpClient
$udpClient.Connect("192.168.1.100", 514)
$mensaje = "<14>1 2026-10-14T21:00:00Z OpenWrt kernel - - [firewall] reject wan in: SRC=203.0.113.50 DST=192.168.1.1 PROTO=TCP SPT=49152 DPT=22"
$bytes = [System.Text.Encoding]::UTF8.GetBytes($mensaje)
$udpClient.Send($bytes, $bytes.Length)
$udpClient.Close()
```

### Resultado Esperado:
1. El registro aparece de inmediato en el panel **Visor de Registros en Tiempo Real** de Grafana en `http://192.168.1.100:3003`.
2. Vector clasifica el evento con `is_security_alert: true` debido al puerto sensible `22`.
3. Vector despacha el evento al `conector_ia_soc.py` (puerto 8088), el cual evalúa la IP `203.0.113.50`, asigna la técnica MITRE `T1110 - Brute Force` y sugiere la regla de bloqueo.
