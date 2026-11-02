#!/usr/bin/env python3
from deploy_soc_compose import get_ssh_client, DOCKER_BIN, DEFAULT_PASS

def print_logs(client, name, tail=30):
    print(f"\n{'='*25} {name} (tail {tail}) {'='*25}")
    cmd = f"echo '{DEFAULT_PASS}' | sudo -S {DOCKER_BIN} logs --tail {tail} {name}"
    stdin, stdout, stderr = client.exec_command(cmd)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    lines = [l for l in (out + "\n" + err).splitlines() if not l.startswith("Password:") and l.strip()]
    if lines:
        for l in lines:
            print(l)
    else:
        print("(No logs)")

def main():
    client = get_ssh_client()
    for name in ["soc_vector", "soc_loki", "soc_grafana", "soc_ai_connector"]:
        print_logs(client, name, 25)
    client.close()

if __name__ == "__main__":
    main()
