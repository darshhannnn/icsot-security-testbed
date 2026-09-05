#!/usr/bin/env python3
"""Live IDS loop: sniff Modbus/TCP, evaluate rules, and store alerts."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ids import db
from ids.rules import RuleEngine, load_config
from ids.sniffer import packet_to_modbus, sniff_modbus


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Passive Modbus/TCP IDS for GRFICSv3-style labs.")
    parser.add_argument("--interface", required=True, help="Network interface to sniff.")
    parser.add_argument("--config", type=Path, required=True, help="Zone/conduit JSON file.")
    parser.add_argument(
        "--approved-hmi",
        required=True,
        help="Comma-separated IPs allowed to issue Modbus write functions "
             "(e.g. the HMI plus the PLC itself, which commands its remote IO).",
    )
    parser.add_argument("--database", type=Path, default=Path("alerts.db"), help="SQLite alert database.")
    parser.add_argument("--rate-window-seconds", type=int, default=10)
    parser.add_argument("--max-requests-per-window", type=int, default=50)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    connection = db.connect(args.database)
    engine = RuleEngine(
        config=load_config(args.config),
        approved_hmi=args.approved_hmi,
        rate_window_seconds=args.rate_window_seconds,
        max_requests_per_window=args.max_requests_per_window,
    )
    print(
        f"[IDS] listening on interface '{args.interface}' for Modbus/TCP port 502 "
        f"(approved writers: {args.approved_hmi}, database: {args.database})",
        flush=True,
    )

    def inspect(packet: object) -> None:
        modbus_packet = packet_to_modbus(packet)
        if modbus_packet is None:
            return

        for alert in engine.evaluate(modbus_packet):
            alert_id = db.insert_alert(connection, alert)
            print(json.dumps({"id": alert_id, **alert.__dict__}, sort_keys=True), flush=True)

    sniff_modbus(args.interface, inspect)


if __name__ == "__main__":
    main()

