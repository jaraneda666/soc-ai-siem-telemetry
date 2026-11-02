#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
# Tool: deploy_soc_compose.py

## Metadata
- Nombre: deploy_soc_compose.py
- Versión: 1.0
- Lenguaje: Python
- Creada en proyecto: Soc_AI
- Fecha de creación: 2026-10-14
- Descripción: Despliega, sincroniza configuraciones y administra el ciclo de vida de la pila de contenedores SOC (Vector, Loki, Grafana, Conector IA) en Synology DSM 7.2.2 vía SSH/Paramiko.
- Parámetros: --action (deploy|up|down|restart|status|logs|test), --service (opcional)
- Dependencias: paramiko, argparse
"""

import os
import sys
import time
import base64
import socket
import argparse
from pathlib import Path
import paramiko

DEFAULT_HOST = os.environ.get("SYNO_HOST", "192.168.1.100")
DEFAULT_PORT = int(os.environ.get("SYNO_PORT", "22"))
DEFAULT_USER = os.environ.get("SYNO_USER", os.environ.get("ADMIN_USER", "admin"))
DEFAULT_PASS = os.environ.get("SYNO_PASS", "")

REMOTE_BASE = "/volume1/docker/soc"
DOCKER_BIN = "/var/packages/ContainerManager/target/usr/bin/docker"


def get_ssh_client(host=DEFAULT_HOST, port=DEFAULT_PORT, user=DEFAULT_USER, password=DEFAULT_PASS):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    key_path = os.path.expanduser("~/.ssh/id_ed25519")
    if os.path.exists(key_path):
        try:
            client.connect(host, port=port, username=user, key_filename=key_path, timeout=10)
            return client
        except Exception:
            pass
    client.connect(host, port=port, username=user, password=password, timeout=10)
    return client


def sudo_exec(client, cmd, password=DEFAULT_PASS):
    full_cmd = f"echo '{password}' | sudo -S {cmd}"
    stdin, stdout, stderr = client.exec_command(full_cmd)
    out = stdout.read().decode("utf-8", errors="replace").strip()
    err = stderr.read().decode("utf-8", errors="replace").strip()
    return out, err


def upload_file_b64(client, local_path: Path, remote_path: str):
    with open(local_path, "rb") as f:
        b64_content = base64.b64encode(f.read()).decode("ascii")

    remote_dir = str(Path(remote_path).parent).replace("\\", "/")
    sudo_exec(client, f"mkdir -p {remote_dir}")
    cmd = f"bash -c 'echo \"{b64_content}\" | base64 -d > {remote_path} && chmod 644 {remote_path}'"
    out, err = sudo_exec(client, cmd)
    return out, err


def action_deploy(client, project_root: Path):
    print(f"[*] Preparando directorios remotos en {REMOTE_BASE}...")
    dirs = [
        f"{REMOTE_BASE}/config/vector",
        f"{REMOTE_BASE}/config/loki",
        f"{REMOTE_BASE}/config/grafana/provisioning/datasources",
        f"{REMOTE_BASE}/config/grafana/provisioning/dashboards",
        f"{REMOTE_BASE}/config/grafana/dashboards",
        f"{REMOTE_BASE}/tools",
        f"{REMOTE_BASE}/data/vector",
        f"{REMOTE_BASE}/data/loki",
        f"{REMOTE_BASE}/data/grafana"
    ]
    for d in dirs:
        sudo_exec(client, f"mkdir -p {d}")

    # Transferencia de archivos
    archivos = [
        ("docker-compose.yml", f"{REMOTE_BASE}/docker-compose.yml"),
        ("config/vector/vector.yaml", f"{REMOTE_BASE}/config/vector/vector.yaml"),
        ("config/loki/loki-config.yaml", f"{REMOTE_BASE}/config/loki/loki-config.yaml"),
        ("config/grafana/provisioning/datasources/datasources.yaml", f"{REMOTE_BASE}/config/grafana/provisioning/datasources/datasources.yaml"),
        ("config/grafana/provisioning/dashboards/dashboards.yaml", f"{REMOTE_BASE}/config/grafana/provisioning/dashboards/dashboards.yaml"),
        ("config/grafana/provisioning/dashboards/soc_network_overview.json", f"{REMOTE_BASE}/config/grafana/provisioning/dashboards/soc_network_overview.json"),
        ("config/grafana/dashboards/soc_network_overview.json", f"{REMOTE_BASE}/config/grafana/dashboards/soc_network_overview.json"),
        ("tools/conector_ia_soc.py", f"{REMOTE_BASE}/tools/conector_ia_soc.py")
    ]

    for local_rel, remote_dest in archivos:
        local_f = project_root / local_rel
        if local_f.exists():
            print(f"  -> Subiendo {local_rel}...")
            upload_file_b64(client, local_f, remote_dest)
        else:
            print(f"  [!] Archivo no encontrado: {local_f}")

    print("[*] Aplicando permisos de ejecución y propiedad de volúmenes...")
    sudo_exec(client, f"chown -R 472:472 {REMOTE_BASE}/data/grafana")
    sudo_exec(client, f"chown -R 10001:10001 {REMOTE_BASE}/data/loki")
    sudo_exec(client, f"chmod -R 775 {REMOTE_BASE}/data")
    print("[+] Sincronización completada exitosamente.")


def action_up(client):
    print(f"[*] Levantando contenedores SOC con Docker Compose en {REMOTE_BASE}...")
    cmd = f"bash -c 'cd {REMOTE_BASE} && {DOCKER_BIN} compose up -d'"
    out, err = sudo_exec(client, cmd)
    print(out)
    if err and "error" in err.lower():
        print(f"[!] Errores detectados: {err}")
    else:
        print("[+] Comando Docker Compose Up ejecutado.")


def action_down(client):
    print(f"[*] Deteniendo contenedores SOC en {REMOTE_BASE}...")
    cmd = f"bash -c 'cd {REMOTE_BASE} && {DOCKER_BIN} compose down'"
    out, err = sudo_exec(client, cmd)
    print(out)
    print("[+] Contenedores detenidos.")


def action_status(client):
    print("[*] Estado de contenedores SOC:")
    cmd = f"{DOCKER_BIN} ps -a --filter 'name=soc_'"
    out, _ = sudo_exec(client, cmd)
    print(out if out else "No hay contenedores soc_* en ejecución.")

    print("\n[*] Estadísticas de memoria y CPU:")
    stats_cmd = f"bash -c \"{DOCKER_BIN} stats --no-stream --format 'table {{{{.Name}}}}\t{{{{.CPUPerc}}}}\t{{{{.MemUsage}}}}\t{{{{.MemPerc}}}}' $({DOCKER_BIN} ps -q --filter 'name=soc_')\""
    out_stats, _ = sudo_exec(client, stats_cmd)
    print(out_stats if out_stats else "Sin estadísticas activas.")


def action_logs(client, service=None, lines=50):
    svc_filter = f"soc_{service}" if service else "soc_"
    print(f"[*] Obteniendo últimos {lines} logs de contenedores ({svc_filter}):")
    cmd = f"bash -c 'for c in $({DOCKER_BIN} ps -a -q --filter name={svc_filter}); do echo \"=== CONTAINER \"$c\" \"$({DOCKER_BIN} inspect --format \\'{{{{.Name}}}}\\' $c)\" ===\"; {DOCKER_BIN} logs --tail {lines} $c; done'"
    out, _ = sudo_exec(client, cmd)
    print(out)


def action_test(target_ip=DEFAULT_HOST, port=514):
    import datetime
    now_ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[*] Enviando paquete de prueba Syslog UDP RFC 5424 ({now_ts}) a {target_ip}:{port}...")
    msg = f"<14>1 {now_ts} OpenWrt kernel - - [firewall] reject wan in: SRC=198.51.100.77 DST=192.168.1.1 PROTO=TCP SPT=54321 DPT=22"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(msg.encode("utf-8"), (target_ip, port))
        print(f"[+] Paquete Syslog enviado con éxito: '{msg}'")
    except Exception as e:
        print(f"[!] Error al enviar paquete: {e}")
    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser(description="Despliegue y gestión de Soc_AI en Synology NAS")
    parser.add_argument("--action", choices=["deploy", "up", "down", "restart", "status", "logs", "test", "full"], default="status", help="Acción a ejecutar")
    parser.add_argument("--service", help="Servidor específico para logs (vector|loki|grafana|ai_connector)")
    parser.add_argument("--host", default=DEFAULT_HOST, help="IP de Synology DSM")
    args = parser.parse_args()

    # Búsqueda robusta de la carpeta Soc_AI
    current = Path(__file__).resolve()
    project_root = None
    for p in [current.parent, current.parent.parent, current.parent.parent.parent]:
        if (p / "Soc_AI" / "docker-compose.yml").exists():
            project_root = p / "Soc_AI"
            break
        elif (p / "docker-compose.yml").exists() and p.name == "Soc_AI":
            project_root = p
            break

    if not project_root:
        project_root = Path.cwd() / "Soc_AI"

    if args.action == "test":
        action_test(args.host, 514)
        return

    print(f"[*] Conectando a Synology NAS en {args.host}:{DEFAULT_PORT} como '{DEFAULT_USER}'...")
    try:
        client = get_ssh_client(args.host, DEFAULT_PORT, DEFAULT_USER, DEFAULT_PASS)
        print("[+] Conexión SSH establecida con éxito.")
    except Exception as e:
        print(f"[!] Error crítico de conexión SSH: {e}")
        sys.exit(1)

    try:
        if args.action == "deploy":
            action_deploy(client, project_root)
        elif args.action == "up":
            action_up(client)
            time.sleep(3)
            action_status(client)
        elif args.action == "down":
            action_down(client)
        elif args.action == "restart":
            action_down(client)
            time.sleep(2)
            action_up(client)
            time.sleep(3)
            action_status(client)
        elif args.action == "status":
            action_status(client)
        elif args.action == "logs":
            action_logs(client, args.service)
        elif args.action == "full":
            action_deploy(client, project_root)
            action_up(client)
            time.sleep(5)
            action_status(client)
            action_test(args.host, 514)
    finally:
        client.close()


if __name__ == "__main__":
    main()
