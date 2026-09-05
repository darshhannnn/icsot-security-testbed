#!/usr/bin/env python3
"""Lab-only zone-boundary probe: one Modbus read from a non-conduit source.

Sends a single read-holding-registers request (FC3) directly to a PLC from
whatever host runs the script. Use it from a host whose IP is NOT listed as
an allowed conduit source in ids/conduits.example.json (e.g. a workstation-
zone or attacker-zone container) to validate the zone_boundary_violation rule.
A read is used deliberately so a fired alert can only come from the
zone-boundary rule, never from the unauthorized-write rule.
"""

from __future__ import annotations

import argparse
import asyncio

from pymodbus.client import AsyncModbusTcpClient


async def probe(target: str, port: int, address: int, count: int, unit_id: int) -> None:
    client = AsyncModbusTcpClient(target, port=port)
    await client.connect()
    if not client.connected:
        raise SystemExit(f"Could not connect to {target}:{port}")

    try:
        result = await client.read_holding_registers(address=address, count=count, slave=unit_id)
        if result.isError():
            raise SystemExit(f"Modbus read returned an error: {result}")
        print(
            f"Read holding registers address={address} count={count} "
            f"from {target}:{port} -> registers {result.registers}"
        )
    finally:
        client.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Send one direct Modbus read to a PLC from a non-conduit source."
    )
    parser.add_argument("--target", required=True, help="Lab PLC IP address.")
    parser.add_argument("--port", type=int, default=502)
    parser.add_argument("--address", type=int, default=0)
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--unit-id", type=int, default=1)
    args = parser.parse_args()

    asyncio.run(probe(args.target, args.port, args.address, args.count, args.unit_id))


if __name__ == "__main__":
    main()
