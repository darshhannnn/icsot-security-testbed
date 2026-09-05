#!/usr/bin/env python3
"""Packet parsing helpers for Modbus/TCP traffic."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

try:
    from scapy.all import IP, TCP, Raw, sniff
except ModuleNotFoundError:
    IP = TCP = Raw = None
    sniff = None


@dataclass(frozen=True)
class ModbusPacket:
    timestamp: float
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    transaction_id: int
    protocol_id: int
    unit_id: int
    function_code: int
    raw_payload: str


def parse_modbus_tcp_payload(raw_bytes: bytes) -> tuple[int, int, int, int] | None:
    """Return transaction ID, protocol ID, unit ID, and function code."""
    if len(raw_bytes) < 8:
        return None

    transaction_id = int.from_bytes(raw_bytes[0:2], "big")
    protocol_id = int.from_bytes(raw_bytes[2:4], "big")
    length = int.from_bytes(raw_bytes[4:6], "big")
    unit_id = raw_bytes[6]
    function_code = raw_bytes[7]

    if protocol_id != 0:
        return None

    expected_minimum_length = 6 + length
    if len(raw_bytes) < expected_minimum_length:
        return None

    return transaction_id, protocol_id, unit_id, function_code


def packet_to_modbus(packet: Any) -> ModbusPacket | None:
    if IP is None or TCP is None or Raw is None:
        raise RuntimeError("scapy is required for packet capture. Install dependencies from requirements.txt.")

    if IP not in packet or TCP not in packet or Raw not in packet:
        return None

    tcp = packet[TCP]
    if tcp.dport != 502 and tcp.sport != 502:
        return None

    raw_bytes = bytes(packet[Raw].load)
    parsed = parse_modbus_tcp_payload(raw_bytes)
    if parsed is None:
        return None

    transaction_id, protocol_id, unit_id, function_code = parsed
    return ModbusPacket(
        timestamp=float(packet.time),
        source_ip=str(packet[IP].src),
        destination_ip=str(packet[IP].dst),
        source_port=int(tcp.sport),
        destination_port=int(tcp.dport),
        transaction_id=transaction_id,
        protocol_id=protocol_id,
        unit_id=unit_id,
        function_code=function_code,
        raw_payload=raw_bytes.hex()[:256],
    )


def sniff_modbus(interface: str, callback: Any) -> None:
    if sniff is None:
        raise RuntimeError("scapy is required for packet capture. Install dependencies from requirements.txt.")

    sniff(iface=interface, filter="tcp port 502", prn=callback, store=False)
