#!/usr/bin/env python3
import sys
from deploy_soc_compose import get_ssh_client, DOCKER_BIN, DEFAULT_PASS

target = sys.argv[1] if len(sys.argv) > 1 else "soc_vector"
lines = int(sys.argv[2]) if len(sys.argv) > 2 else 50

client = get_ssh_client()
cmd = f"echo '{DEFAULT_PASS}' | sudo -S {DOCKER_BIN} logs --tail {lines} {target}"
stdin, stdout, stderr = client.exec_command(cmd)
out = stdout.read().decode("utf-8", errors="replace")
err = stderr.read().decode("utf-8", errors="replace")
all_lines = [l for l in (out + "\n" + err).splitlines() if not l.startswith("Password:") and l.strip()]

print(f"=== LOGS DE {target} (últimas {len(all_lines)} líneas) ===")
for l in all_lines:
    print(l)
client.close()
