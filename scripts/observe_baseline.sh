#!/usr/bin/env bash
set -euo pipefail
# Determine the PLC's Modbus-facing interface and observe baseline traffic
# from inside the PLC's network namespace.
PLC_IFACE=$(docker exec plc sh -c 'ls /sys/class/net' | grep -v -E '^(lo|eth0)$' | head -n1)
echo "PLC interfaces: $(docker exec plc sh -c 'ls /sys/class/net | tr "\n" " "')"
echo "Chosen Modbus iface: $PLC_IFACE"
docker exec plc sh -c 'cat /proc/net/fib_trie' 2>/dev/null | grep -A1 "192.168.95" | head -4 || true
docker run --rm --network container:plc \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -e PYTHONPATH=/work \
  -v "/mnt/e/Unreg/ICSOT Security Testbed:/work" -w /work \
  ids-lab-tools python scripts/observe_traffic.py --interface "$PLC_IFACE" --seconds 30
