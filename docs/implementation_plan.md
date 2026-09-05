# Implementation Plan

## Phase 1: Understand the Topology

Goal: Establish the before-state architecture.

Tasks:

1. Deploy GRFICSv3 and verify that the simulation, PLC, HMI, workstation, and router containers are healthy.
2. Record container names, Docker networks, IP addresses, and exposed ports.
3. Map each component to an IEC 62443-style zone.
4. Capture baseline traffic between components, especially Modbus/TCP on port 502.
5. Save screenshots, packet captures, and command output references in `docs/evidence_log.md`.

Outputs:

- Completed zone/conduit table.
- Baseline traffic notes.
- Before-state architecture diagram.

## Phase 2: Segmentation and Conduits

Goal: Replace flat access with explicit allowed conduits.

Tasks:

1. Configure the GRFICSv3 router container as the enforcement point.
2. Allow HMI-to-PLC Modbus/TCP on port 502.
3. Block engineering workstation-to-PLC writes by default.
4. Add a documented maintenance exception for engineering workstation access.
5. Test allowed and blocked flows.

Outputs:

- Router/firewall rule evidence.
- Updated target-state zone/conduit table.
- Blocked-flow test evidence.

## Phase 3: Modbus IDS

Goal: Add passive visibility for unsafe Modbus behavior.

Detection rules:

1. Unauthorized write function codes: 5, 6, 15, and 16 from any source other than the approved HMI.
2. Zone-boundary violations where traffic does not match the conduit table.
3. Request-rate spikes that suggest scanning, flooding, or crude denial-of-service behavior.

Outputs:

- Running IDS.
- Alert dashboard.
- Sample alert logs.

## Phase 4: Attack Simulation and Evidence

Goal: Demonstrate before/after control value.

Tasks:

1. Attempt unauthorized Modbus writes from a non-HMI source.
2. Generate higher-rate Modbus requests to trigger spike detection.
3. Optionally use Fortiphyd `caldera-modbus` for richer adversary emulation.
4. Capture IDS alerts and segmentation blocks.

Outputs:

- Before/after evidence.
- Alert screenshots.
- Packet captures or log excerpts.

## Phase 5: Documentation

Goal: Package the work as portfolio and compliance evidence.

Final artifacts:

- README.
- Architecture diagram.
- Zone/conduit table.
- Detection logic summary.
- Alert log samples.
- Exception record for maintenance access.
- Resume bullets.

## Acceptance Criteria

- GRFICSv3 is running with documented topology.
- Segmentation is enforced according to the zone/conduit table.
- IDS detects unauthorized writes, zone-boundary violations, and request-rate spikes.
- Dashboard shows alert summary and detail views.
- At least two scenarios have before/after evidence in `docs/evidence/`.
