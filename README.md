# OT/ICS Security Testbed

Containerized IEC 62443-style security lab for GRFICSv3, focused on Modbus/TCP segmentation, detection, and evidence capture.

## What This Project Adds

- A phase-by-phase implementation plan for GRFICSv3.
- Zone and conduit documentation suitable for architecture evidence.
- A lightweight passive Modbus IDS that flags unauthorized writes, zone-boundary violations, and request-rate spikes.
- SQLite alert storage for repeatable evidence.
- A small Flask dashboard for reviewing alerts and raw packet details.
- Controlled lab traffic helpers for unauthorized-write and flood validation.

## Base GRFICSv3 Setup

Run this from a Linux host or WSL2 environment with Docker enabled:

```bash
sudo apt update
sudo apt install -y git git-lfs docker.io docker-compose-plugin
git clone https://github.com/Fortiphyd/GRFICSv3.git
cd GRFICSv3
./build.sh
docker compose up -d
```

Then open:

```text
http://localhost
```

## Project Layout

```text
docs/
  architecture.md
  implementation_plan.md
  zone_conduit_table.md
  evidence/
  evidence_log.md
ids/
  sniffer.py
  rules.py
  detector.py
  db.py
  conduits.example.json
dashboard/
  app.py
  templates/
attacks/
  unauthorized_write.py
  flood.py
  mitm_notes.md
segmentation/
  router_rules.md
scripts/
  setup_grfics.sh
requirements.txt
```

## Quick IDS Run

Install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Start the passive IDS. Replace the interface and IPs after confirming the GRFICSv3 Docker network.

```bash
python ids/detector.py \
  --interface eth0 \
  --config ids/conduits.example.json \
  --approved-hmi 172.20.0.20 \
  --database alerts.db
```

Start the alert dashboard:

```bash
python dashboard/app.py --database alerts.db --host 0.0.0.0 --port 8080
```

Open:

```text
http://localhost:8080
```

## Lab Validation

Use the test helper only against your GRFICSv3 PLC container:

```bash
python attacks/unauthorized_write.py --target 172.20.0.10 --address 1 --value 1
```

Generate request-rate traffic for the flood rule:

```bash
python attacks/flood.py --target 172.20.0.10 --count 75 --delay 0.02
```

Expected result:

- Before controls: write traffic reaches the PLC and no alert exists.
- After IDS: unauthorized write function code is logged.
- After segmentation: traffic outside allowed conduits is blocked by router/firewall policy.

## Detection Rules

| Rule | Trigger | Severity |
| --- | --- | --- |
| Unauthorized Modbus write | Function codes 5, 6, 15, or 16 from any source other than the approved HMI | High |
| Zone-boundary violation | TCP/502 request does not match `ids/conduits.example.json` | High |
| Request-rate spike | One source exceeds the configured request threshold inside the rolling window | Medium |

## Before/After Validation Matrix

| Scenario | Baseline Expected Result | Controlled Expected Result | Evidence |
| --- | --- | --- | --- |
| Unauthorized write | Write reaches PLC silently | IDS alert and/or router block | `docs/evidence/` |
| Flood request burst | High-rate reads reach PLC silently | IDS rate alert | `docs/evidence/` |
| MITM or command-injection attempt | Manipulated command path succeeds or is not visible | IDS alert and/or router block | `docs/evidence/` |

## Limitations and Future Work

- Container IPs and GRFICSv3 service names must be confirmed on the deployment host.
- The IDS is passive; segmentation enforcement still depends on router/firewall rules.
- Modbus/TCP is the first protocol. OPC UA, DNP3, and Ethernet/IP would make strong extensions.
- Real PLC hardware or a dedicated virtual firewall would improve realism.
- Evasion testing, allowlisted maintenance windows, and richer process-aware rules are natural next steps.

## Deliverables

The finished lab should produce:

- Architecture diagram of zones and conduits.
- Zone/conduit table with allowed ports, sources, destinations, and rationale.
- Router/firewall rule evidence.
- IDS rule descriptions.
- Alert logs showing detection of unauthorized writes and abnormal traffic.
- Before/after screenshots or packet captures.

## Acceptance Criteria

- [ ] GRFICSv3 running with documented topology.
- [ ] Enforced segmentation matching the zone/conduit table.
- [ ] Working IDS detecting all three rule types.
- [ ] Alerts visible in the dashboard.
- [ ] At least two attack scenarios demonstrated with before/after evidence.
- [ ] README and docs suitable for a GitHub portfolio entry.
