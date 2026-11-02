#!/usr/bin/env python3
import urllib.request
import urllib.parse
import json
import datetime
import time
import sys

# Forzar salida segura para Windows cp1252
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

LOKI_URL = "http://192.168.1.100:3100"

def query_loki(query, limit=50, start_hours_ago=24):
    now_ns = int(time.time() * 1e9)
    start_ns = int((time.time() - start_hours_ago * 3600) * 1e9)
    params = urllib.parse.urlencode({
        "query": query,
        "limit": limit,
        "start": start_ns,
        "end": now_ns
    })
    url = f"{LOKI_URL}/loki/api/v1/query_range?{params}"
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            return data.get("data", {}).get("result", [])
    except Exception as e:
        print(f"Error querying '{query}': {e}")
        return []

def main():
    print("=" * 60)
    print("AUDITORÍA DE LOGS Y EVENTOS EN EL STACK SOC_AI (LOKI / SYS_LOGS)")
    print("=" * 60)

    # 1. Alertas de seguridad
    print("\n[1] ALERTAS DE SEGURIDAD (últimas 24h)")
    alerts = query_loki('{is_alert="true"}', limit=20)
    if not alerts:
        alerts = query_loki('{is_security_alert="true"}', limit=20)
    if alerts:
        total = sum(len(s.get("values", [])) for s in alerts)
        print(f" -> Encontradas {total} alertas registradas:")
        for s in alerts:
            for v in s.get("values", [])[:10]:
                try:
                    ev = json.loads(v[1])
                    ip = ev.get('ip_origen') or ev.get('source_ip') or 'N/A'
                    port = ev.get('puerto_destino') or ev.get('target_port') or 'N/A'
                    print(f"    • [{ev.get('severidad', 'N/A')}] IP: {ip} -> Puerto: {port} | MITRE: {ev.get('tecnica_mitre')} | Acción: {ev.get('accion_automatica')} | Diag: {ev.get('diagnostico_ia', '')[:80]}...")
                except Exception:
                    print(f"    • {v[1][:120]}...")
    else:
        print(" -> No hay alertas de seguridad críticas en las últimas 24h.")

    # 2. Intentos de autenticación fallidos (SSH / Dropbear / DSM)
    print("\n[2] INTENTOS FALLIDOS DE ACCESO / FUERZA BRUTA (SSH / Web / DSM)")
    auth_fails = query_loki('{source_type="syslog"} |~ "(?i)(bad password|login failed|auth fail|failed password)"', limit=20)
    if auth_fails:
        total = sum(len(s.get("values", [])) for s in auth_fails)
        print(f" -> Encontrados {total} eventos de fallo de autenticación:")
        for s in auth_fails:
            for v in s.get("values", [])[:10]:
                print(f"    • {v[1]}")
    else:
        print(" -> No se detectaron fallos de autenticación o ataques de fuerza bruta recientes.")

    # 3. Errores de interfaz física o caídas de enlaces (Router / Switch / APs)
    print("\n[3] EVENTOS DE INTERFAZ / ERRORES DE PUERTO O ENLACE")
    link_events = query_loki('{event_category="port_status"} | json | errores > 0', limit=20)
    if link_events:
        total = sum(len(s.get("values", [])) for s in link_events)
        print(f" -> Encontrados {total} registros con errores de interfaz:")
        for s in link_events:
            for v in s.get("values", [])[:10]:
                print(f"    • {v[1]}")
    else:
        print(" -> Puertos físicos sin errores de transmisión/recepción (0 errores).")

    # 4. Errores generales en Syslog (kernel / daemon errors)
    print("\n[4] ERRORES EN REGISTROS DE SISTEMA (syslog severity=error/err)")
    sys_errors = query_loki('{source_type="syslog", severity=~"err|error|crit|alert|emerg"}', limit=20)
    if sys_errors:
        total = sum(len(s.get("values", [])) for s in sys_errors)
        print(f" -> Encontrados {total} registros de severidad error/crítica:")
        for s in sys_errors:
            for v in s.get("values", [])[:10]:
                print(f"    • {v[1]}")
    else:
        print(" -> Sin errores de severidad crítica/error en syslog.")

    # 5. Descartes de cortafuegos más frecuentes (Top puertos atacados)
    print("\n[5] DESCARTE DE TRÁFICO WAN (Top ataques descartados por Firewall)")
    fw_drops = query_loki('{event_category="firewall_reject"}', limit=50)
    if fw_drops:
        total = sum(len(s.get("values", [])) for s in fw_drops)
        ports = {}
        src_ips = {}
        for s in fw_drops:
            for v in s.get("values", []):
                try:
                    ev = json.loads(v[1])
                    p = ev.get("target_port")
                    ip = ev.get("source_ip")
                    if p:
                        ports[p] = ports.get(p, 0) + 1
                    if ip:
                        src_ips[ip] = src_ips.get(ip, 0) + 1
                except Exception:
                    pass
        print(f" -> Total muestras recientes analizadas: {total}")
        top_ports = sorted(ports.items(), key=lambda x: x[1], reverse=True)[:5]
        top_ips = sorted(src_ips.items(), key=lambda x: x[1], reverse=True)[:5]
        print(f"    • Top Puertos WAN bloqueados: {top_ports}")
        print(f"    • Top IPs atacantes bloqueadas en WAN: {top_ips}")

if __name__ == "__main__":
    main()
