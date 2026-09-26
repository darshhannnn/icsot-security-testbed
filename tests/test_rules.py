#!/usr/bin/env python3
"""Sanity tests for the IDS detection rules (no packet capture required).

Run:  python tests/test_rules.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ids.rules import (  # noqa: E402
    RuleEngine,
    conduit_allowed,
    detect_unauthorized_write,
    load_config,
)
from ids.sniffer import ModbusPacket  # noqa: E402

CONFIG = load_config(ROOT / "ids" / "conduits.example.json")
ENGINE = RuleEngine(CONFIG, "192.168.90.107,192.168.95.2", 10, 300)


def packet(src="192.168.90.99", dst="192.168.95.2", fc=6, dport=502, ts=1000.0):
    return ModbusPacket(
        timestamp=ts, source_ip=src, destination_ip=dst,
        source_port=44444, destination_port=dport, transaction_id=1,
        protocol_id=0, unit_id=1, function_code=fc, raw_payload="aa"*8,
    )


def test_unauthorized_write_fires_for_non_writer():
    alerts = ENGINE.evaluate(packet(fc=6))
    assert any(a.rule == "unauthorized_modbus_write" for a in alerts), alerts
    print("PASS unauthorized write fires for non-approved writer (fc=6)")


def test_unauthorized_write_allows_hmi_and_plc():
    assert detect_unauthorized_write(packet(src="192.168.90.107", fc=5), ENGINE.approved_writers) is None
    assert detect_unauthorized_write(packet(src="192.168.95.2", dst="192.168.95.10", fc=16), ENGINE.approved_writers) is None
    print("PASS HMI and PLC writes are not flagged")


def test_zone_boundary():
    alerts = ENGINE.evaluate(packet(src="192.168.90.99", fc=3))
    assert any(a.rule == "zone_boundary_violation" for a in alerts), alerts
    assert conduit_allowed(CONFIG, "192.168.90.107", "192.168.95.2", 502)
    assert not conduit_allowed(CONFIG, "192.168.90.99", "192.168.95.2", 502)
    print("PASS zone boundary fires for non-conduit pair, allows HMI->PLC")


def test_rate_anomaly_threshold_and_reset():
    ts = 2000.0
    fired = False
    for i in range(301):
        p = packet(src="192.168.90.99", fc=3, ts=ts + i * 0.01)
        alerts = ENGINE.detect_rate_anomaly(p)
        if alerts and not fired:
            assert alerts[0] == "request_rate_spike"
            assert alerts[1] == "medium"
            assert "301 Modbus requests" in alerts[2]
            fired = True
    assert fired, "rate rule never fired at 301 requests/10s"

    # after the 10s window passes, the pair's counter must reset
    p_after = packet(src="192.168.90.99", fc=3, ts=ts + 30.0)
    assert ENGINE.detect_rate_anomaly(p_after) is None, "rate state did not reset"
    print("PASS rate spike fires over threshold and resets after the window")


def test_normal_rate_not_flagged():
    # HMI polling pace: ~1.5 req/s -> 15 per 10s window, well under 300
    for i in range(15):
        p = packet(src="192.168.90.107", fc=3, ts=3000.0 + i * 0.66)
        assert ENGINE.detect_rate_anomaly(p) is None
    print("PASS legitimate HMI request rate is not flagged")


if __name__ == "__main__":
    test_unauthorized_write_fires_for_non_writer()
    test_unauthorized_write_allows_hmi_and_plc()
    test_zone_boundary()
    test_rate_anomaly_threshold_and_reset()
    test_normal_rate_not_flagged()
    print("ALL RULE TESTS PASSED")
