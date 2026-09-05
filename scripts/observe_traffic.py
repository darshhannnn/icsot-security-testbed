#!/usr/bin/env python3
"""Observe live Modbus/TCP traffic in a network namespace (baseline capture).

Runs inside a container sharing the PLC's network namespace. Prints one
summary line per second: per-(source, destination, function-code) request
counts, so the baseline process traffic can be characterized before the IDS
rules are armed.
"""

from __future__ import annotations

import argparse
import time
from collections import Counter

from scapy.all import IP, TCP, sniff

from ids.sniffer import packet_to_modbus


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", required=True)
    parser.add_argument("--seconds", type=int, default=30)
    args = parser.parse_args()

    counts: Counter[str] = Counter()
    end = time.time() + args.seconds

    def show() -> None:
        print(f"--- t={time.strftime('%H:%M:%S')} ---", flush=True)
        for key, n in sorted(counts.items()):
            print(f"  {key}: {n}", flush=True)
        counts.clear()

    def handle(packet: object) -> None:
        mb = packet_to_modbus(packet)
        if mb is None:
            return
        if mb.destination_port == 502:
            counts[f"req  {mb.source_ip}->{mb.destination_ip} fc={mb.function_code}"] += 1
        else:
            counts[f"resp {mb.destination_ip}->{mb.source_ip} fc={mb.function_code}"] += 1

    print(f"[observe] sniffing {args.interface} for {args.seconds}s ...", flush=True)
    sniff(iface=args.interface, filter="tcp port 502", prn=handle, store=False,
          timeout=args.seconds, promisc=True)
    show()
    print("[observe] done", flush=True)


if __name__ == "__main__":
    main()
