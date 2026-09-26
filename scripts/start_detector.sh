#!/usr/bin/env bash
set -euo pipefail
REPO="/mnt/e/Unreg/ICSOT Security Testbed"
PLC_IFACE=$(docker exec plc sh -c 'ls /sys/class/net' | grep -v -E '^(lo|eth0)$' | head -n1)
echo "PLC_IFACE=$PLC_IFACE"
docker rm -f ids-detector >/dev/null 2>&1 || true
docker run -d --name ids-detector \
  --network container:plc \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -v "$REPO:/work" -v ids_alerts:/data -w /work \
  ids-lab-tools \
  python ids/detector.py \
    --interface "$PLC_IFACE" \
    --config ids/conduits.example.json \
    --approved-hmi "192.168.90.107,192.168.95.2" \
    --rate-window-seconds 10 \
    --max-requests-per-window 300 \
    --database /data/alerts.db
sleep 3
docker logs ids-detector
