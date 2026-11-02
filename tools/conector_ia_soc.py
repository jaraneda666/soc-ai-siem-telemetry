#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
conector_ia_soc.py — Microservicio de Enlace de Eventos y Correlación IA
Recibe eventos de seguridad desde Vector, aplica reducción de frecuencia (rate limit),
consulta al modelo de lenguaje (Ollama o API) para clasificación MITRE ATT&CK
y despacha recomendaciones de mitigación supervisadas hacia Telegram.
"""

import os
import sys
import json
import time
import logging
import urllib.request
import urllib.error
import ipaddress
import socket
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

# Configuración de registro
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("SocAIConnector")

# Variables de entorno
PORT = int(os.getenv("PORT", "8088"))
OLLAMA_ENDPOINT = os.getenv("OLLAMA_ENDPOINT", "http://127.0.0.1:11434/api/generate")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b")
LOKI_ENDPOINT = os.getenv("LOKI_ENDPOINT", "http://loki:3100/loki/api/v1/push")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

# Configuración de Respuesta Activa (OpenWrt)
OPENWRT_HOST = os.getenv("OPENWRT_HOST", "192.168.1.1")
OPENWRT_USER = os.getenv("OPENWRT_USER", "root")
OPENWRT_KEY_PATH = os.getenv("OPENWRT_KEY_PATH", "/app/ssh/id_ed25519")
BAN_TIMEOUT = os.getenv("BAN_TIMEOUT", "1h")

# Configuración de Telemetría de Puertos Físicos
SWITCH_HOST = os.getenv("SWITCH_HOST", "192.168.1.252")
SWITCH_COMMUNITY = os.getenv("SWITCH_COMMUNITY", os.environ.get("ADMIN_USER", "admin"))
PORT_POLL_INTERVAL = int(os.getenv("PORT_POLL_INTERVAL", "20"))

# Lista blanca estricta de subredes locales y rangos reservados
WHITELIST_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),     # CGNAT
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local
    ipaddress.ip_network("224.0.0.0/4"),       # Multicast
    ipaddress.ip_network("240.0.0.0/4"),       # Reservado
]

# Caché en memoria para deduplicación (IP -> timestamp)
CACHE_HISTORIAL = {}
TIEMPO_SUPRESION_SEGUNDOS = 300  # 5 minutos


def es_ip_protegida(ip_str: str) -> bool:
    """Verifica si la IP pertenece a la red local (LAN) o rangos reservados protegidos."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            return True
        for net in WHITELIST_NETWORKS:
            if ip in net:
                return True
        return False
    except ValueError:
        return True


def aplicar_bloqueo_openwrt(ip_str: str, duracion: str = BAN_TIMEOUT) -> tuple[bool, str]:
    """Aplica un bloqueo dinámico con expiración en el cortafuegos OpenWrt nftables inet banIP."""
    if es_ip_protegida(ip_str):
        msg = f"IP {ip_str} protegida en lista blanca (LAN / RFC 1918). Bloqueo omitido."
        logger.warning(msg)
        return False, msg

    if not os.path.exists(OPENWRT_KEY_PATH):
        msg = f"Clave SSH no encontrada en {OPENWRT_KEY_PATH}. Bloqueo omitido."
        logger.error(msg)
        return False, msg

    try:
        import paramiko
        key = paramiko.Ed25519Key.from_private_key_file(OPENWRT_KEY_PATH)
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(OPENWRT_HOST, 22, username=OPENWRT_USER, pkey=key, timeout=5)

        cmd = f"nft add element inet banIP blocklist.v4 {{ {ip_str} timeout {duracion} }}"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        err = stderr.read().decode("utf-8").strip()
        ssh.close()

        if err:
            logger.error(f"Fallo al ejecutar bloqueo en OpenWrt: {err}")
            return False, f"Error OpenWrt: {err}"

        success_msg = f"🚫 [ACTIVE RESPONSE] IP atacante {ip_str} bloqueada en OpenWrt por {duracion}."
        logger.info(success_msg)
        return True, f"🚫 Bloqueada automáticamente en OpenWrt ({duracion})"
    except Exception as e:
        logger.error(f"Error de conexión SSH con OpenWrt: {e}")
        return False, f"Fallo SSH OpenWrt: {e}"


def consultar_modelo_ia(datos_evento: dict) -> dict:
    """Envía el evento anómalo a Ollama y obtiene clasificación MITRE y mitigación."""
    prompt = f"""Eres un analista de ciberseguridad defensiva en un SOC.
Analiza el siguiente incidente de red y clasifícalo objetivamente:
- IP Origen: {datos_evento.get('source_ip', 'Desconocida')}
- Puerto Destino: {datos_evento.get('target_port', 'Desconocido')}
- Dispositivo Detector: {datos_evento.get('device_type', 'Desconocido')}
- Categoría: {datos_evento.get('event_category', 'Desconocida')}
- Motivo de Alerta: {datos_evento.get('alert_reason', '')}
- Registro Crudo: {datos_evento.get('message', '')}

Responde estrictamente en formato JSON válido con las siguientes claves:
{{
  "tecnica_mitre": "Código Txxxx y nombre formal",
  "severidad": "Baja / Media / Alta / Crítica",
  "diagnostico": "Explicación concisa y técnica del riesgo detectado",
  "solucion": "Breve resumen de la solución y pasos de remediación recomendados",
  "comando_openwrt": "Comando uci/nftables exacto para mitigar",
  "comando_synology": "Comando de cortafuegos de Synology"
}}
"""
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "format": "json"
    }

    try:
        req = urllib.request.Request(
            OLLAMA_ENDPOINT,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=4) as resp:
            resultado = json.loads(resp.read().decode("utf-8"))
            respuesta_texto = resultado.get("response", "{}")
            return json.loads(respuesta_texto)
    except Exception as e:
        logger.warning(f"No fue posible contactar con Ollama ({e}). Aplicando análisis heurístico local.")
        # Análisis heurístico alternativo ante indisponibilidad del modelo
        dpt = datos_evento.get("target_port", 0)
        tecnica = "T1595 - Active Scanning"
        severidad = "Media"
        if dpt in [22, 23]:
            tecnica = "T1110 - Brute Force"
            severidad = "Alta"
        elif dpt in [5000, 5001]:
            tecnica = "T1190 - Exploit Public-Facing Application"
            severidad = "Alta"

        src_ip = datos_evento.get("source_ip", "0.0.0.0")
        return {
            "tecnica_mitre": tecnica,
            "severidad": severidad,
            "diagnostico": f"Tráfico recurrente detectado hacia el puerto sensible {dpt}.",
            "solucion": f"Bloquear la dirección IP {src_ip} en el cortafuegos perimetral del router.",
            "comando_openwrt": f"uci add_list firewall.@rule[-1].src_ip='{src_ip}' && uci commit firewall && /etc/init.d/firewall reload",
            "comando_synology": f"iptables -I INPUT -s {src_ip} -j DROP"
        }


def inyectar_alerta_enriquecida_loki(datos_evento: dict, analisis_ia: dict, estado_bloqueo: str = "No ejecutado"):
    """Inyecta el evento analizado con IA estructurado en Loki para visualización nativa en Grafana."""
    now_ns = str(int(time.time() * 1e9))
    payload_evento = {
        "diagnostico_ia": analisis_ia.get("diagnostico", "Diagnóstico no disponible"),
        "solucion_sugerida": analisis_ia.get("solucion", "Bloquear tráfico sospechoso en cortafuegos"),
        "accion_automatica": estado_bloqueo,
        "tecnica_mitre": analisis_ia.get("tecnica_mitre", "N/A"),
        "severidad": analisis_ia.get("severidad", "Media"),
        "comando_mitigacion_openwrt": analisis_ia.get("comando_openwrt", ""),
        "comando_mitigacion_synology": analisis_ia.get("comando_synology", ""),
        "ip_origen": datos_evento.get("source_ip", "0.0.0.0"),
        "puerto_destino": datos_evento.get("target_port", 0),
        "dispositivo": datos_evento.get("device_type", "network_device"),
        "motivo_alerta": datos_evento.get("alert_reason", "Incidente de seguridad detectado"),
        "mensaje_original": datos_evento.get("message", "")
    }

    stream_payload = {
        "streams": [
            {
                "stream": {
                    "source_type": "syslog",
                    "device_type": datos_evento.get("device_type", "network_device"),
                    "event_category": "security_incident",
                    "is_alert": "true",
                    "ia_enriched": "true"
                },
                "values": [
                    [now_ns, json.dumps(payload_evento, ensure_ascii=False)]
                ]
            }
        ]
    }

    try:
        req = urllib.request.Request(
            LOKI_ENDPOINT,
            data=json.dumps(stream_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status in [200, 204]:
                logger.info(f"Alerta enriquecida inyectada exitosamente en Loki para {datos_evento.get('source_ip')}")
    except Exception as e:
        logger.error(f"Error al inyectar alerta enriquecida en Loki: {e}")


def despachar_alerta_telegram(datos_evento: dict, analisis_ia: dict, estado_bloqueo: str = ""):
    """Envía notificación estructurada a Telegram si las credenciales están configuradas."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        logger.info("Telegram no configurado. Evento procesado en consola.")
        return

    src_ip = datos_evento.get("source_ip", "N/A")
    dpt = datos_evento.get("target_port", "N/A")
    dev = datos_evento.get("device_type", "N/A")

    texto = (
        f"🚨 *ALERTA SOC_AI — INCIDENTE DETECTADO*\n\n"
        f"• *Origen:* `{src_ip}`\n"
        f"• *Destino / Puerto:* `{dpt}`\n"
        f"• *Dispositivo:* `{dev}`\n"
        f"• *Severidad:* *{analisis_ia.get('severidad', 'N/A')}*\n"
        f"• *Técnica MITRE:* `{analisis_ia.get('tecnica_mitre', 'N/A')}`\n\n"
        f"📋 *Diagnóstico IA:*\n{analisis_ia.get('diagnostico', '')}\n\n"
        f"🛡️ *Respuesta Activa:*\n`{estado_bloqueo}`\n\n"
        f"⚙️ *Comando de Bloqueo Manual OpenWrt:*\n`{analisis_ia.get('comando_openwrt', '')}`"
    )

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": texto,
        "parse_mode": "Markdown"
    }

    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            pass
    except Exception as e:
        logger.error(f"Error al enviar mensaje a Telegram: {e}")


def build_snmp_get(community: str, oid_list: list[int], req_id_num: int = 1) -> bytes:
    oid_bytes = bytearray()
    oid_bytes.append(oid_list[0] * 40 + oid_list[1])
    for val in oid_list[2:]:
        if val < 128:
            oid_bytes.append(val)
        else:
            buf = []
            while val > 0:
                buf.append(val & 0x7F)
                val >>= 7
            buf.reverse()
            for b in buf[:-1]:
                oid_bytes.append(b | 0x80)
            oid_bytes.append(buf[-1])

    encoded_oid = bytes([0x06, len(oid_bytes)]) + bytes(oid_bytes)
    varbind = bytes([0x30, len(encoded_oid) + 2]) + encoded_oid + bytes([0x05, 0x00])
    varbind_list = bytes([0x30, len(varbind)]) + varbind

    req_id = bytes([0x02, 0x01, req_id_num & 0xFF])
    err_status = bytes([0x02, 0x01, 0x00])
    err_index = bytes([0x02, 0x01, 0x00])
    pdu_body = req_id + err_status + err_index + varbind_list
    pdu = bytes([0xA0, len(pdu_body)]) + pdu_body

    version = bytes([0x02, 0x01, 0x01])  # SNMP v2c
    comm_bytes = community.encode("ascii")
    comm = bytes([0x04, len(comm_bytes)]) + comm_bytes

    msg_body = version + comm + pdu
    return bytes([0x30, len(msg_body)]) + msg_body


def query_snmp_val(host: str, community: str, oid: list[int]) -> int:
    pkt = build_snmp_get(community, oid)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1.5)
    try:
        s.sendto(pkt, (host, 161))
        resp, _ = s.recvfrom(2048)
        for l in [1, 2, 4, 8]:
            tag_pos = len(resp) - l - 2
            if tag_pos >= 0 and resp[tag_pos] in (0x02, 0x41, 0x42):
                if resp[tag_pos + 1] == l:
                    val = 0
                    for b in resp[tag_pos + 2:]:
                        val = (val << 8) | b
                    return val
        return resp[-1]
    finally:
        s.close()


def recolectar_puertos_switch() -> list[dict]:
    puertos = []
    for p in range(1, 9):
        try:
            st = query_snmp_val(SWITCH_HOST, SWITCH_COMMUNITY, [1, 3, 6, 1, 2, 1, 2, 2, 1, 8, p])
            sp = query_snmp_val(SWITCH_HOST, SWITCH_COMMUNITY, [1, 3, 6, 1, 2, 1, 2, 2, 1, 5, p])
            rx_p = query_snmp_val(SWITCH_HOST, SWITCH_COMMUNITY, [1, 3, 6, 1, 2, 1, 2, 2, 1, 11, p])
            tx_p = query_snmp_val(SWITCH_HOST, SWITCH_COMMUNITY, [1, 3, 6, 1, 2, 1, 2, 2, 1, 17, p])
            rx_err = query_snmp_val(SWITCH_HOST, SWITCH_COMMUNITY, [1, 3, 6, 1, 2, 1, 2, 2, 1, 14, p])
            tx_err = query_snmp_val(SWITCH_HOST, SWITCH_COMMUNITY, [1, 3, 6, 1, 2, 1, 2, 2, 1, 20, p])

            is_up = (st == 1)
            mbps = sp // 1000000 if sp > 0 else 0
            speed_str = f"{mbps} Mbps" if mbps < 1000 else f"{mbps//1000} Gbps"
            if not is_up:
                speed_str = "Desconectado"
            speed_text = f"{mbps}M" if mbps < 1000 else f"{mbps//1000}G"
            if not is_up:
                speed_text = "Down"

            puertos.append({
                "device": "Switch US-8-60W",
                "dispositivo": "Switch US-8-60W",
                "port": f"Port {p}",
                "puerto": f"Port {p}",
                "status": "UP" if is_up else "DOWN",
                "estado": "UP" if is_up else "DOWN",
                "status_code": 1 if is_up else 0,
                "speed_mbps": mbps if is_up else 0,
                "speed": speed_str,
                "velocidad": speed_str,
                "speed_text": speed_text,
                "paquetes_rx": rx_p if is_up else 0,
                "paquetes_tx": tx_p if is_up else 0,
                "errores": (rx_err + tx_err) if is_up else 0
            })
        except Exception as e:
            logger.debug(f"Error consultando puerto {p} de switch: {e}")
    return puertos


def recolectar_puertos_router() -> list[dict]:
    puertos = []
    if not os.path.exists(OPENWRT_KEY_PATH):
        return puertos
    try:
        import paramiko
        k = paramiko.Ed25519Key.from_private_key_file(OPENWRT_KEY_PATH)
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(OPENWRT_HOST, username=OPENWRT_USER, pkey=k, timeout=4)

        cmd = "for p in wan lan1 lan2 lan3 lan4; do c=0; s=0; rx_p=0; tx_p=0; rx_e=0; tx_e=0; [ -f /sys/class/net/$p/carrier ] && c=$(cat /sys/class/net/$p/carrier 2>/dev/null || echo 0); [ -f /sys/class/net/$p/speed ] && s=$(cat /sys/class/net/$p/speed 2>/dev/null || echo 0); [ -f /sys/class/net/$p/statistics/rx_packets ] && rx_p=$(cat /sys/class/net/$p/statistics/rx_packets 2>/dev/null || echo 0); [ -f /sys/class/net/$p/statistics/tx_packets ] && tx_p=$(cat /sys/class/net/$p/statistics/tx_packets 2>/dev/null || echo 0); [ -f /sys/class/net/$p/statistics/rx_errors ] && rx_e=$(cat /sys/class/net/$p/statistics/rx_errors 2>/dev/null || echo 0); [ -f /sys/class/net/$p/statistics/tx_errors ] && tx_e=$(cat /sys/class/net/$p/statistics/tx_errors 2>/dev/null || echo 0); echo \"$p|$c|$s|$rx_p|$tx_p|$((rx_e + tx_e))\"; done"
        stdin, stdout, stderr = c.exec_command(cmd)
        out = stdout.read().decode().strip()
        c.close()

        port_map = {"wan": "WAN", "lan1": "LAN 1", "lan2": "LAN 2", "lan3": "LAN 3", "lan4": "LAN 4"}
        for line in out.split("\n"):
            if "|" in line:
                parts = line.split("|")
                raw_p, carrier, speed_str, rx_p, tx_p, errs = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
                is_up = (carrier.strip() == "1")
                try:
                    s_int = int(speed_str.strip())
                except ValueError:
                    s_int = 0
                s_int = max(0, s_int)
                spd_formatted = f"{s_int} Mbps" if s_int < 1000 else f"{s_int//1000} Gbps"
                if not is_up:
                    spd_formatted = "Desconectado"
                speed_text = f"{s_int}M" if s_int < 1000 else f"{s_int//1000}G"
                if not is_up:
                    speed_text = "Down"

                puertos.append({
                    "device": "Router OpenWrt",
                    "dispositivo": "Router OpenWrt",
                    "port": port_map.get(raw_p.strip(), raw_p.strip().upper()),
                    "puerto": port_map.get(raw_p.strip(), raw_p.strip().upper()),
                    "status": "UP" if is_up else "DOWN",
                    "estado": "UP" if is_up else "DOWN",
                    "status_code": 1 if is_up else 0,
                    "speed_mbps": s_int if is_up else 0,
                    "speed": spd_formatted,
                    "velocidad": spd_formatted,
                    "speed_text": speed_text,
                    "paquetes_rx": int(rx_p) if is_up else 0,
                    "paquetes_tx": int(tx_p) if is_up else 0,
                    "errores": int(errs) if is_up else 0
                })
    except Exception as e:
        logger.debug(f"Error consultando puertos de router: {e}")
    return puertos


def inyectar_telemetria_puertos_loki(puertos: list[dict]):
    if not puertos:
        return
    now_ns = str(int(time.time() * 1e9))
    streams = []
    for p in puertos:
        stream = {
            "stream": {
                "source_type": "telemetry",
                "device_type": "network_switch" if "Switch" in p["device"] else "router_openwrt",
                "event_category": "port_status",
                "device_name": p["device"],
                "port_name": p["port"]
            },
            "values": [
                [now_ns, json.dumps(p, ensure_ascii=False)]
            ]
        }
        streams.append(stream)

    payload = {"streams": streams}
    try:
        req = urllib.request.Request(
            LOKI_ENDPOINT,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            pass
    except Exception as e:
        logger.error(f"Error inyectando telemetría de puertos a Loki: {e}")


def bucle_telemetria_puertos():
    logger.info("Hilo de telemetría de puertos físicos iniciado.")
    time.sleep(5)
    while True:
        try:
            sw_ports = recolectar_puertos_switch()
            rt_ports = recolectar_puertos_router()
            todos = sw_ports + rt_ports
            if todos:
                inyectar_telemetria_puertos_loki(todos)
        except Exception as e:
            logger.error(f"Excepción en bucle de telemetría de puertos: {e}")
        time.sleep(PORT_POLL_INTERVAL)


class HandlerWebhook(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/alert":
            longitud = int(self.headers.get("Content-Length", 0))
            cuerpo = self.rfile.read(longitud).decode("utf-8")

            try:
                cuerpo = cuerpo.strip()
                eventos = []
                if cuerpo.startswith("["):
                    eventos = json.loads(cuerpo)
                elif "\n" in cuerpo:
                    for linea in cuerpo.splitlines():
                        linea = linea.strip()
                        if linea:
                            eventos.append(json.loads(linea))
                else:
                    evento_obj = json.loads(cuerpo)
                    eventos = [evento_obj] if isinstance(evento_obj, dict) else evento_obj

                ahora = time.time()
                for evento in eventos:
                    src_ip = evento.get("source_ip")
                    # Filtrar eventos sin IP o deduplicar
                    if not src_ip or src_ip in ["0.0.0.0", "127.0.0.1"]:
                        continue

                    ultimo_visto = CACHE_HISTORIAL.get(src_ip, 0)
                    if ahora - ultimo_visto < TIEMPO_SUPRESION_SEGUNDOS:
                        logger.debug(f"Evento desde {src_ip} suprimido por ventana de deduplicación.")
                        continue

                    CACHE_HISTORIAL[src_ip] = ahora
                    logger.info(f"Procesando alerta de seguridad: IP={src_ip}, Puerto={evento.get('target_port')}")

                    # Procesamiento con IA
                    analisis = consultar_modelo_ia(evento)
                    logger.info(f"Resultado IA: MITRE={analisis.get('tecnica_mitre')}, Severidad={analisis.get('severidad')}")

                    # Respuesta Activa Automatizada: Bloqueo perimetral en OpenWrt (con Whitelist)
                    exito_bloqueo, estado_bloqueo = aplicar_bloqueo_openwrt(src_ip)

                    # Inyección estructurada en Loki para visualización nativa en Grafana
                    inyectar_alerta_enriquecida_loki(evento, analisis, estado_bloqueo)

                    # Notificación supervisada
                    despachar_alerta_telegram(evento, analisis, estado_bloqueo)

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status":"processed"}')
            except Exception as e:
                logger.error(f"Error al procesar payload de alerta: {e}")
                self.send_response(400)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"healthy","uptime":true}')
        else:
            self.send_response(404)
            self.end_headers()


def iniciar_servidor():
    # Hilo en segundo plano para sondeo periódico de puertos físicos (Router y Switch)
    t = threading.Thread(target=bucle_telemetria_puertos, daemon=True, name="PortTelemetryThread")
    t.start()

    servidor = HTTPServer(("0.0.0.0", PORT), HandlerWebhook)
    logger.info(f"Microservicio de Enlace IA iniciado en el puerto {PORT}")
    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        logger.info("Deteniendo servidor...")
        servidor.server_close()


if __name__ == "__main__":
    iniciar_servidor()
