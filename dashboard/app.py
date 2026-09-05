#!/usr/bin/env python3
"""Flask dashboard for the SQLite-backed Modbus IDS."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from flask import Flask, abort, render_template

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ids import db


def create_app(database: Path) -> Flask:
    app = Flask(__name__)

    @app.get("/")
    def index() -> str:
        connection = db.connect(database)
        try:
            alerts = db.list_alerts(connection)
            counts_by_rule = db.counts_by(connection, "rule")
            counts_by_severity = db.counts_by(connection, "severity")
        finally:
            connection.close()
        return render_template(
            "index.html",
            alerts=alerts,
            counts_by_rule=counts_by_rule,
            counts_by_severity=counts_by_severity,
        )

    @app.get("/alerts/<int:alert_id>")
    def detail(alert_id: int) -> str:
        connection = db.connect(database)
        try:
            alert = db.get_alert(connection, alert_id)
        finally:
            connection.close()
        if alert is None:
            abort(404)
        return render_template("detail.html", alert=alert)

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="Render IDS alerts from a SQLite database.")
    parser.add_argument("--database", type=Path, default=Path("alerts.db"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    create_app(args.database).run(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
