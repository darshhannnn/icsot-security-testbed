#!/usr/bin/env python3
"""Detection rules for Modbus/TCP traffic."""

from __future__ import annotations

import json
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ids.sniffer import ModbusPacket


WRITE_FUNCTION_CODES = {5, 6, 15, 16}


@dataclass(frozen=True)
class Alert:
    timestamp: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    function_code: int
    rule: str
    severity: str
    raw_payload: str
    detail: str


class RuleEngine:
    def __init__(
        self,
        config: dict[str, Any],
        approved_hmi: str,
        rate_window_seconds: int,
        max_requests_per_window: int,
    ) -> None:
        self.config = config
        # Comma-separated list of IPs allowed to issue Modbus write functions.
        # The GRFICSv3 process loop makes the PLC itself a legitimate writer:
        # OpenPLC commands its remote-IO devices (FC6/FC16) continuously, so
        # restricting writes to the HMI alone would alert on normal operation.
        self.approved_writers = {ip.strip() for ip in approved_hmi.split(",") if ip.strip()}
        self.rate_window_seconds = rate_window_seconds
        self.max_requests_per_window = max_requests_per_window
        # Rate tracking is per (source, destination) pair, not per source:
        # the PLC legitimately polls each remote-IO device ~186 times per
        # 10s window, so source-only counting would flag normal operation.
        self.request_times: dict[tuple[str, str], deque[float]] = defaultdict(deque)

    def evaluate(self, packet: ModbusPacket) -> list[Alert]:
        alerts = []

        unauthorized = detect_unauthorized_write(packet, self.approved_writers)
        if unauthorized:
            alerts.append(self._build_alert(packet, *unauthorized))

        conduit = detect_zone_boundary_violation(packet, self.config)
        if conduit:
            alerts.append(self._build_alert(packet, *conduit))

        flood = self.detect_rate_anomaly(packet)
        if flood:
            alerts.append(self._build_alert(packet, *flood))

        return alerts

    def detect_rate_anomaly(self, packet: ModbusPacket) -> tuple[str, str, str] | None:
        if packet.destination_port != 502:
            return None

        request_times = self.request_times[(packet.source_ip, packet.destination_ip)]
        request_times.append(packet.timestamp)
        cutoff = packet.timestamp - self.rate_window_seconds
        while request_times and request_times[0] < cutoff:
            request_times.popleft()

        if len(request_times) <= self.max_requests_per_window:
            return None

        detail = (
            f"{packet.source_ip} sent {len(request_times)} Modbus requests to "
            f"{packet.destination_ip} in {self.rate_window_seconds} seconds"
        )
        return "request_rate_spike", "medium", detail

    @staticmethod
    def _build_alert(packet: ModbusPacket, rule: str, severity: str, detail: str) -> Alert:
        return Alert(
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(packet.timestamp)),
            source_ip=packet.source_ip,
            destination_ip=packet.destination_ip,
            source_port=packet.source_port,
            destination_port=packet.destination_port,
            function_code=packet.function_code,
            rule=rule,
            severity=severity,
            raw_payload=packet.raw_payload,
            detail=detail,
        )


def load_config(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def detect_unauthorized_write(
    packet: ModbusPacket,
    approved_writers: set[str],
) -> tuple[str, str, str] | None:
    if packet.destination_port != 502:
        return None

    if packet.function_code not in WRITE_FUNCTION_CODES:
        return None

    if packet.source_ip in approved_writers:
        return None

    detail = (
        f"Modbus write function {packet.function_code} originated from "
        f"{packet.source_ip}, not an approved writer "
        f"({', '.join(sorted(approved_writers))})"
    )
    return "unauthorized_modbus_write", "high", detail


def detect_zone_boundary_violation(
    packet: ModbusPacket,
    config: dict[str, Any],
) -> tuple[str, str, str] | None:
    if packet.destination_port != 502:
        return None

    if conduit_allowed(config, packet.source_ip, packet.destination_ip, packet.destination_port):
        return None

    src_zone = config.get("zones", {}).get(packet.source_ip, {}).get("zone", "unknown")
    dst_zone = config.get("zones", {}).get(packet.destination_ip, {}).get("zone", "unknown")
    detail = (
        f"No allowed conduit for {packet.source_ip} ({src_zone}) to "
        f"{packet.destination_ip} ({dst_zone}) on TCP/{packet.destination_port}"
    )
    return "zone_boundary_violation", "high", detail


def conduit_allowed(config: dict[str, Any], source: str, destination: str, port: int) -> bool:
    for conduit in config.get("allowed_conduits", []):
        if (
            conduit.get("source") == source
            and conduit.get("destination") == destination
            and int(conduit.get("port", 0)) == port
            and conduit.get("protocol", "").lower() == "tcp"
        ):
            return True
    return False

