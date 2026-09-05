#!/usr/bin/env python3
"""Lab-only Modbus write helper for validating IDS and segmentation controls."""

from __future__ import annotations

import argparse
import asyncio

from pymodbus.client import AsyncModbusTcpClient


async def write_coil(target: str, port: int, address: int, value: bool, unit_id: int) -> None:
    client = AsyncModbusTcpClient(target, port=port)
    await client.connect()
    if not client.connected:
        raise SystemExit(f"Could not connect to {target}:{port}")

    try:
        result = await client.write_coil(address=address, value=value, slave=unit_id)
        if result.isError():
            raise SystemExit(f"Modbus write returned an error: {result}")
        print(f"Wrote coil address={address} value={int(value)} on {target}:{port}")
    finally:
        client.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Send one explicit Modbus write to a lab PLC.")
    parser.add_argument("--target", required=True, help="Lab PLC IP address.")
    parser.add_argument("--port", type=int, default=502)
    parser.add_argument("--address", type=int, required=True)
    parser.add_argument("--value", type=int, choices=[0, 1], required=True)
    parser.add_argument("--unit-id", type=int, default=1)
    args = parser.parse_args()

    asyncio.run(write_coil(args.target, args.port, args.address, bool(args.value), args.unit_id))


if __name__ == "__main__":
    main()

