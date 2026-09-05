#!/usr/bin/env bash
cd "/mnt/e/Unreg/ICSOT Security Testbed/GRFICSv3" || exit 1
docker compose ps
echo "=== container IPs ==="
for c in plc HMI EWS simulation router; do
  ips=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}={{$v.IPAddress}} {{end}}' "$c")
  echo "$c -> $ips"
done
echo "=== networks ==="
docker network ls --format '{{.Name}} ({{.Driver}})'
echo "=== plc interfaces ==="
docker exec plc ip -o -4 addr
echo "=== published ports ==="
docker compose ps --format json | python3 -c 'import json,sys
for line in sys.stdin:
    d = json.loads(line)
    print(d.get("Name"), d.get("Publishers", ""))' 2>/dev/null || docker port plc; docker port simulation
