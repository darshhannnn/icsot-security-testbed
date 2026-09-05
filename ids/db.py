#!/usr/bin/env python3
"""SQLite storage for IDS alerts."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from ids.rules import Alert


SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL,
  source_ip TEXT NOT NULL,
  destination_ip TEXT NOT NULL,
  source_port INTEGER NOT NULL,
  destination_port INTEGER NOT NULL,
  function_code INTEGER NOT NULL,
  rule TEXT NOT NULL,
  severity TEXT NOT NULL,
  raw_payload TEXT NOT NULL,
  detail TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
"""


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.executescript(SCHEMA)
    connection.commit()
    return connection


def insert_alert(connection: sqlite3.Connection, alert: Alert) -> int:
    cursor = connection.execute(
        """
        INSERT INTO alerts (
          timestamp, source_ip, destination_ip, source_port, destination_port,
          function_code, rule, severity, raw_payload, detail
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            alert.timestamp,
            alert.source_ip,
            alert.destination_ip,
            alert.source_port,
            alert.destination_port,
            alert.function_code,
            alert.rule,
            alert.severity,
            alert.raw_payload,
            alert.detail,
        ),
    )
    connection.commit()
    return int(cursor.lastrowid)


def list_alerts(connection: sqlite3.Connection, limit: int = 200) -> list[dict[str, Any]]:
    rows = connection.execute(
        "SELECT * FROM alerts ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


def get_alert(connection: sqlite3.Connection, alert_id: int) -> dict[str, Any] | None:
    row = connection.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    return dict(row) if row else None


def counts_by(connection: sqlite3.Connection, column: str) -> dict[str, int]:
    if column not in {"rule", "severity"}:
        raise ValueError("Unsupported count column")

    rows = connection.execute(
        f"SELECT {column} AS name, COUNT(*) AS count FROM alerts GROUP BY {column} ORDER BY count DESC"
    ).fetchall()
    return {str(row["name"]): int(row["count"]) for row in rows}

