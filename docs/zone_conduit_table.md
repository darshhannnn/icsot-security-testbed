# IEC 62443-Style Zone and Conduit Table

Update IP addresses after running `docker compose ps` and inspecting the GRFICSv3 networks.

## Zones

| Zone | Purpose | GRFICSv3 Components | Example IPs | Security Intent |
| --- | --- | --- | --- | --- |
| Zone 0 | Physical process simulation | 3D chemical process simulation | TBD | Represents process state and plant behavior. |
| Zone 1 | Basic control | PLC | `172.20.0.10` | Only authorized supervisory systems should issue control commands. |
| Zone 2 | Supervisory control | HMI, engineering workstation | `172.20.0.20`, `172.20.0.30` | Operators monitor and control the process; engineering access is exceptional. |
| Zone 3 | Site operations / DMZ | Router, optional firewall | `172.20.0.1` | Enforces conduits between zones and external access. |

## Conduits

| ID | Source Zone | Source Component | Destination Zone | Destination Component | Protocol/Port | Default Action | Rationale |
| --- | --- | --- | --- | --- | --- | --- | --- |
| C-001 | Zone 2 | HMI | Zone 1 | PLC | Modbus/TCP 502 | Allow | Required for normal operator control. |
| C-002 | Zone 2 | Engineering workstation | Zone 1 | PLC | Modbus/TCP 502 | Deny | Engineering writes should not be continuously available. |
| C-003 | Zone 2 | Engineering workstation | Zone 1 | PLC | Modbus/TCP 502 | Time-bound allow | Maintenance exception only, with approval and logging. |
| C-004 | Zone 3 | External host | Zone 1 | PLC | Any | Deny | Direct external control access is not required. |
| C-005 | Zone 1 | PLC | Zone 0 | Simulation | GRFICS protocol traffic | Allow | Required for the lab process loop. |

## Maintenance Exception Record

| Field | Value |
| --- | --- |
| Exception ID | EX-001 |
| Requestor | TBD |
| Source | Engineering workstation |
| Destination | PLC |
| Protocol/Port | Modbus/TCP 502 |
| Start Time | TBD |
| End Time | TBD |
| Approval | TBD |
| Compensating Control | IDS enabled; packet capture retained. |
| Closure Evidence | TBD |

