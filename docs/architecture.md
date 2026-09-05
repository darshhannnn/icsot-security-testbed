# Architecture

## Target Topology

```text
              External / Host Access
                       |
                 Zone 3: Router
                       |
        +--------------+--------------+
        |                             |
 Zone 2: Supervisory             Zone 1: Control
 HMI, Engineering WS  --502-->   PLC
                                      |
                                Zone 0: Process
                                3D simulation
```

## Zone Mapping

| Zone | Role | GRFICSv3 Components | Notes |
| --- | --- | --- | --- |
| Zone 0 | Physical process simulation | 3D chemical plant simulation | Represents process behavior and physical state. |
| Zone 1 | Basic control | PLC | Receives Modbus/TCP requests and controls the simulated process. |
| Zone 2 | Supervisory | HMI, engineering workstation | HMI is approved for normal PLC interaction; engineering access is exceptional. |
| Zone 3 | DMZ / routing | Router, optional firewall container | Enforces the allowed conduits and blocks direct unauthorized paths. |

## Baseline State

The baseline GRFICSv3 deployment should be treated as flat or permissive until proven otherwise. During Phase 1, capture:

- Container names and IP addresses.
- Docker networks and subnets.
- Normal HMI-to-PLC Modbus/TCP traffic.
- Any engineering workstation-to-PLC reachability.
- Host-to-container exposure.

## Target State

The target state is a zone/conduit model:

- HMI to PLC on Modbus/TCP port 502 is allowed.
- Engineering workstation to PLC is denied by default.
- Engineering workstation to PLC may be temporarily allowed under a maintenance exception.
- External or host-originated direct PLC access is denied.
- IDS visibility is passive and does not sit inline with plant traffic.

