#!/usr/bin/env python3
"""Lab-only Modbus request-rate test for validating flood detection."""

from __future__ import annotations

import argparse
import asyncio

from pymodbus.client import AsyncModbusTcpClient


async def run_flood(target: str, port: int, count: int, delay: float, unit_id: int) -> None:
    client = AsyncModbusTcpClient(target, port=port)
    await client.connect()
    if not client.connected:
        raise SystemExit(f"Could not connect to {target}:{port}")

    try:
        for index in range(count):
            result = await client.read_coils(address=0, count=1, slave=unit_id)
            if result.isError():
                print(f"{index + 1}/{count}: Modbus error {result}")
            else:
                print(f"{index + 1}/{count}: request sent")
            if delay:
                await asyncio.sleep(delay)
    finally:
        client.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Send repeated Modbus reads to test rate alerts.")
    parser.add_argument("--target", required=True, help="Lab PLC IP address.")
    parser.add_argument("--port", type=int, default=502)
    parser.add_argument("--count", type=int, default=75)
    parser.add_argument("--delay", type=float, default=0.02)
    parser.add_argument("--unit-id", type=int, default=1)
    args = parser.parse_args()

    asyncio.run(run_flood(args.target, args.port, args.count, args.delay, args.unit_id))


if __name__ == "__main__":
    main()

