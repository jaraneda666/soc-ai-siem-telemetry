# SOC SIEM Telemetry & Detection Lab

Entorno de laboratorio para ingestión, análisis y procesamiento masivo de registros de auditoría y eventos de red (Syslog, Event IDs de Windows, Wazuh).

---

## Arquitectura y Componentes

- **Ingesta:** Módulos de filtrado y normalización de eventos de seguridad.
- **Reglas:** Reglas de detección correlacionadas con la matriz MITRE ATT&CK Enterprise.
- **Contenedores:** Despliegue de servicios auxiliares mediante Docker Compose.

---

## Instrucciones de Uso

```bash
# Verificación de servicios y contenedores de laboratorio
docker compose ps
```

---

## Consideraciones de Seguridad

- Este repositorio almacena código fuente, utilitarios de prueba y documentación técnica de ingeniería.
- Todas las credenciales, llaves privadas y variables de entorno deben suministrarse de forma local mediante archivos no versionados.
- Las herramientas de auditoría contenidas deben utilizarse exclusivamente en entornos autorizados y laboratorios de prueba.

---

**Autor:** Security Analyst  
**Licencia:** Uso Privado / Propietario
