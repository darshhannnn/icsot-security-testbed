# Router / Firewall Rules

The target state is default-deny between zones, with only documented conduits allowed.

## Policy Summary

| Rule ID | Source | Destination | Protocol/Port | Action | Notes |
| --- | --- | --- | --- | --- | --- |
| FW-001 | HMI | PLC | TCP/502 | Allow | Normal Modbus/TCP operator path. |
| FW-002 | Engineering workstation | PLC | TCP/502 | Deny | Default state. Allow only during approved maintenance. |
| FW-003 | External host | PLC | Any | Deny | No direct external control-plane access. |
| FW-004 | PLC | Simulation | Required GRFICS traffic | Allow | Preserve process loop. Confirm exact ports after topology mapping. |
| FW-999 | Any | Any | Any | Deny | Final default-deny rule. |

## Example iptables Pattern

Adjust interfaces and IP addresses after inspecting GRFICSv3 container networks.

```bash
iptables -P FORWARD DROP
iptables -A FORWARD -s 172.20.0.20 -d 172.20.0.10 -p tcp --dport 502 -j ACCEPT
iptables -A FORWARD -s 172.20.0.30 -d 172.20.0.10 -p tcp --dport 502 -j DROP
iptables -A FORWARD -d 172.20.0.10 -j DROP
```

## Verification

| Test | Expected Result | Evidence |
| --- | --- | --- |
| HMI reads/writes PLC over TCP/502 | Allowed | Packet capture plus normal HMI behavior. |
| Engineering workstation writes PLC outside maintenance window | Blocked | Failed client request plus router log. |
| External host reaches PLC | Blocked | Failed connection attempt. |

