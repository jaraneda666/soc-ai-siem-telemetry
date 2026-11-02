# Guía de Despliegue: SOC Ligero con IA en Synology DSM 7.2.2

Esta guía describe el procedimiento técnico para desplegar la pila de observabilidad y correlación de seguridad (`Vector` + `Loki` + `Grafana` + `Conector IA`) mediante Container Manager en el NAS Synology.

---

## 1. Preparación de Directorios y Permisos en Synology

Conéctate vía SSH al NAS Synology (`192.168.1.100`) con tu usuario administrador:

```bash
ssh admin@192.168.1.100
```

Crea la estructura de carpetas en el volumen principal de Docker (`/volume1/docker/soc/`):

```bash
sudo mkdir -p /volume1/docker/soc/config/vector
sudo mkdir -p /volume1/docker/soc/config/loki
sudo mkdir -p /volume1/docker/soc/config/grafana/provisioning/datasources
sudo mkdir -p /volume1/docker/soc/config/grafana/provisioning/dashboards
sudo mkdir -p /volume1/docker/soc/config/grafana/dashboards
sudo mkdir -p /volume1/docker/soc/tools
sudo mkdir -p /volume1/docker/soc/data/vector
sudo mkdir -p /volume1/docker/soc/data/loki
sudo mkdir -p /volume1/docker/soc/data/grafana
```

Ajusta los permisos de propiedad para los usuarios de ejecución de los contenedores (Grafana UID 472, Loki UID 10001):

```bash
sudo chown -R 472:472 /volume1/docker/soc/data/grafana
sudo chown -R 10001:10001 /volume1/docker/soc/data/loki
sudo chmod -R 775 /volume1/docker/soc/data
```

---

## 2. Transferencia de Archivos de Configuración

Copia los archivos generados en este proyecto hacia el NAS mediante SCP o rsync desde tu estación de trabajo:

```powershell
# Ejecutar desde PowerShell en tu PC:
scp docker-compose.yml admin@192.168.1.100:/volume1/docker/soc/
scp config/vector/vector.yaml admin@192.168.1.100:/volume1/docker/soc/config/vector/
scp config/loki/loki-config.yaml admin@192.168.1.100:/volume1/docker/soc/config/loki/
scp config/grafana/provisioning/datasources/datasources.yaml admin@192.168.1.100:/volume1/docker/soc/config/grafana/provisioning/datasources/
scp config/grafana/provisioning/dashboards/dashboards.yaml admin@192.168.1.100:/volume1/docker/soc/config/grafana/provisioning/dashboards/
scp config/grafana/dashboards/soc_network_overview.json admin@192.168.1.100:/volume1/docker/soc/config/grafana/dashboards/
scp tools/conector_ia_soc.py admin@192.168.1.100:/volume1/docker/soc/tools/
```

---

## 3. Despliegue de los Contenedores con Docker Compose

Desde la terminal SSH en el NAS Synology:

```bash
cd /volume1/docker/soc
sudo /var/packages/ContainerManager/target/usr/bin/docker compose up -d
```

Verifica el estado de los contenedores y el uso de recursos:

```bash
sudo /var/packages/ContainerManager/target/usr/bin/docker compose ps
sudo /var/packages/ContainerManager/target/usr/bin/docker stats --no-stream
```

El consumo combinado de memoria de los cuatro contenedores debe mantenerse por debajo de los 600 MB.

---

## 4. Verificación de Puertos y Servicios

Comprueba que los sockets requeridos se encuentren a la escucha:

- **Syslog UDP/TCP 514:** Receptor de eventos de red de Vector.
- **HTTP 3100:** Interfaz de API de Grafana Loki.
- **HTTP 3003:** Consola web de Grafana (acceso local en `http://192.168.1.100:3003`).
- **HTTP 8088:** Microservicio webhook de correlación con IA.

Comando de verificación rápida:

```bash
sudo netstat -tulpn | grep -E '514|3100|3003|8088'
```

---

## 5. Publicación Segura en Proxy Inverso Nginx de Synology

Para acceder a Grafana desde un subdominio institucional (ej. `grafana.admin.synology.me`) protegiendo el acceso:

1. Ingresa a **DSM > Panel de Control > Portal de Inicio de Sesión > Avanzado > Proxy Inverso**.
2. Crea una regla con los siguientes parámetros:
   - **Nombre:** SOC Grafana
   - **Origen:** HTTPS, nombre de host `grafana.admin.synology.me`, puerto `443`, HSTS habilitado.
   - **Perfil de Control de Acceso:** Selecciona obligatoriamente el perfil `LAN_y_VPN` (para restringir el panel exclusivamente a `192.168.1.0/24` y OpenVPN `10.8.0.0/24`).
   - **Destino:** HTTP, `localhost`, puerto `3003`.
   - **Encabezados personalizados:** WebSocket (`Upgrade: $http_upgrade`, `Connection: $connection_upgrade`).
3. Guarda los cambios para aplicar la configuración sin reinicio del sistema.
