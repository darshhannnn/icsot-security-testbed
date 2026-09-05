#!/usr/bin/env bash
# Verified bring-up + validation sequence for the OT security testbed.
#
# Order matters: GRFICSv3 first (the IDS sidecar shares the PLC's network
# namespace), then the lab-tools image, then IDS + dashboard, then attacks.
#
# Assumes: Linux or WSL2 with Docker + Docker Compose, GRFICSv3 cloned into
# ./GRFICSv3 (see scripts/setup_grfics.sh). Everything below was executed on
# WSL2 Ubuntu 24.04 with Docker 29.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
APPROVED_WRITERS="192.168.90.107,192.168.95.2"  # HMI setpoints + PLC's own actuator writes
PLC_IP="192.168.95.2"
RATE_MAX_PER_WINDOW=300   # measured baseline: PLC polls each IO pair ~186 req/10s
DASHBOARD_PORT="${DASHBOARD_PORT:-8090}"

echo "== 1. Start GRFICSv3 core (simulation, PLC, HMI, router, EWS) =="
docker compose -f "$REPO_DIR/GRFICSv3/docker-compose.yml" \
               -f "$REPO_DIR/GRFICSv3/docker-compose.override.yml" up -d \
               simulation plc hmi router ews

echo "== 2. Build the lab tools image (python + scapy + pymodbus + flask) =="
docker build -t ids-lab-tools -f "$REPO_DIR/scripts/Dockerfile.tools" "$REPO_DIR"

echo "== 3. Start the IDS detector (sidecar in the PLC's network namespace) =="
PLC_IFACE="$(docker exec plc ip -o -4 addr show to "${PLC_IP}/24" | awk '{print $2}' | head -n1)"
echo "PLC Modbus interface: ${PLC_IFACE}"
docker rm -f ids-detector >/dev/null 2>&1 || true
docker run -d --name ids-detector \
  --network container:plc \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -v "$REPO_DIR:/work" -v ids_alerts:/data -w /work \
  ids-lab-tools \
  python ids/detector.py \
    --interface "$PLC_IFACE" \
    --config ids/conduits.example.json \
    --approved-hmi "$APPROVED_WRITERS" \
    --rate-window-seconds 10 \
    --max-requests-per-window "$RATE_MAX_PER_WINDOW" \
    --database /data/alerts.db
sleep 2
docker logs ids-detector

echo "== 4. Start the alert dashboard =="
docker rm -f ids-dashboard >/dev/null 2>&1 || true
docker run -d --name ids-dashboard \
  -p "${DASHBOARD_PORT}:8080" \
  -v "$REPO_DIR:/work" -v ids_alerts:/data -w /work \
  ids-lab-tools \
  python dashboard/app.py --database /data/alerts.db --host 0.0.0.0 --port 8080
echo "Dashboard: http://localhost:${DASHBOARD_PORT}"

echo "== 5. Validation traffic (run manually, in this order) =="
cat <<EOF
# Unauthorized write from an unauthorized DMZ host (expect: unauthorized_modbus_write alert)
docker run --rm --network grficsv3_c-dmz-net --ip 192.168.90.99 \\
  -v "$REPO_DIR:/work" -w /work ids-lab-tools \\
  python attacks/unauthorized_write.py --target ${PLC_IP} --address 1 --value 1

# Flood of Modbus reads from the same host (expect: request_rate_spike alert)
docker run --rm --network grficsv3_c-dmz-net --ip 192.168.90.99 \\
  -v "$REPO_DIR:/work" -w /work ids-lab-tools \\
  python attacks/flood.py --target ${PLC_IP} --count 75 --delay 0.02

# Zone-boundary violation: workstation-zone host -> PLC, bypassing the HMI
# (expect: zone_boundary_violation alert)
docker run --rm --network grficsv3_b-ics-net --ip 192.168.95.99 \\
  -v "$REPO_DIR:/work" -w /work ids-lab-tools \\
  python attacks/unauthorized_write.py --target ${PLC_IP} --address 2 --value 0

# Negative test: wait >10s (rate window) and confirm legitimate process
# traffic (PLC -> remote-IO polls, HMI -> PLC reads) produces no alerts.
EOF
