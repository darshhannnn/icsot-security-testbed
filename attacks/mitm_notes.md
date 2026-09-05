# MITM / Command-Injection Validation Notes

Use this only inside the GRFICSv3 lab network that you own or are authorized to test.

## Option A: Fortiphyd caldera-modbus

1. Clone the project next to GRFICSv3:

   ```bash
   git clone https://github.com/Fortiphyd/caldera-modbus.git
   ```

2. Follow its repository instructions to connect it to the GRFICSv3 Modbus segment.
3. Run one scripted action that attempts a write or command manipulation against the PLC.
4. Keep these evidence points:

   - Attack command and timestamp.
   - PLC/HMI behavior during the run.
   - IDS alert IDs from the dashboard.
   - Router/firewall block logs if segmentation prevented the path.

## Option B: Manual MITM Notes

If you do not use caldera-modbus, document the scenario rather than building a general-purpose MITM tool:

| Field | Value |
| --- | --- |
| Scenario ID | MITM-001 |
| Preconditions | GRFICSv3 running; IDS active; packet capture active. |
| Source | TBD |
| Target | PLC on TCP/502 |
| Attempted Change | TBD |
| Expected Detection | Unauthorized write or zone-boundary violation. |
| Evidence Location | `docs/evidence/` |

