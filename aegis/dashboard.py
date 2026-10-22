"""Flask dashboard: live view over the SQLite history plus a /metrics endpoint.

Read-only by design.  The dashboard never triggers scans, so it can be exposed
to a wider audience than the CI credentials that produce the data.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from flask import Flask, Response, jsonify, render_template, request

from . import charts
from .config import AegisConfig, load_config
from .exceptions_store import ExceptionError, ExceptionStore
from .metrics import collect_store
from .reporting import human_size
from .storage import ScanStore

log = logging.getLogger("aegis.dashboard")

TEMPLATE_DIR = Path(__file__).parent / "dashboard_templates"


def _trend_bars(rows: list[dict[str, Any]]) -> list[charts.StackedBar]:
    return [
        charts.StackedBar(
            label=row["day"][5:],  # MM-DD
            values={
                "CRITICAL": row["critical"] or 0,
                "HIGH": row["high"] or 0,
                "MEDIUM": row["medium"] or 0,
                "LOW": row["low"] or 0,
            },
        )
        for row in rows
    ]


def create_app(config: AegisConfig | None = None) -> Flask:
    config = config or load_config(None)
    app = Flask(__name__, template_folder=str(TEMPLATE_DIR))
    app.config["AEGIS"] = config

    def store() -> ScanStore:
        return ScanStore(config.resolve(config.storage.database))

    def exception_store() -> ExceptionStore:
        return ExceptionStore.load(config.resolve(config.exceptions.file))

    # -- pages ---------------------------------------------------------------

    @app.route("/")
    def overview() -> str:
        db = store()
        days = request.args.get("days", default=30, type=int)
        images = db.images()

        spark: dict[str, str] = {}
        for row in images:
            history = db.scans(image=row["image"], limit=12)
            values = [scan["critical"] + scan["high"] for scan in reversed(history)]
            spark[row["image"]] = charts.sparkline(values)

        packages = [
            charts.StackedBar(
                label=pkg["package"],
                values={
                    "CRITICAL": pkg["critical"] or 0,
                    "HIGH": pkg["high"] or 0,
                    "MEDIUM": pkg["medium"] or 0,
                    "LOW": (pkg["low"] or 0) + (pkg["unknown"] or 0),
                },
            )
            for pkg in db.top_packages(limit=10, days=days)
        ]

        return render_template(
            "overview.html",
            summary=db.summary(),
            images=images,
            sparklines=spark,
            days=days,
            top_packages=packages,
            trend_chart=charts.stacked_bars(_trend_bars(db.trend(days=days)), title="Findings over time"),
            packages_chart=charts.horizontal_bars(packages),
            legend=charts.legend(),
        )

    @app.route("/image/<path:image>")
    def image_page(image: str) -> str:
        db = store()
        days = request.args.get("days", default=30, type=int)
        latest = db.latest_scan(image)
        findings = db.findings(latest["scan_id"]) if latest else []
        reasons: list[str] = []
        if latest and latest.get("reasons"):
            import json

            try:
                reasons = json.loads(latest["reasons"])
            except (ValueError, TypeError):
                reasons = []
        return render_template(
            "image.html",
            image=image,
            latest=latest,
            findings=findings,
            reasons=reasons,
            days=days,
            image_size=human_size(latest["image_size_bytes"]) if latest else "unknown",
            trend_chart=charts.stacked_bars(_trend_bars(db.trend(image=image, days=days))),
            legend=charts.legend(),
        )

    @app.route("/scans")
    def scans_page() -> str:
        db = store()
        days = request.args.get("days", default=30, type=int)
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
        rows = db.scans(image=request.args.get("image") or None, since=since, limit=500)
        verdict = request.args.get("verdict")
        if verdict:
            rows = [row for row in rows if row["verdict"] == verdict]
        return render_template("scans.html", rows=rows, days=days)

    @app.route("/exceptions")
    def exceptions_page() -> str:
        path = config.resolve(config.exceptions.file)
        error = None
        entries: list[dict[str, Any]] = []
        try:
            for entry in exception_store().entries:
                entries.append({**entry.to_dict(), "vuln_id": entry.vuln_id, "days": entry.days_remaining()})
        except ExceptionError as exc:
            error = str(exc)
        entries.sort(key=lambda e: e["expires"])
        return render_template(
            "exceptions.html",
            entries=entries,
            path=path,
            error=error,
            warn_days=config.exceptions.warn_on_expiring_within_days,
        )

    # -- JSON API ------------------------------------------------------------

    @app.route("/api/summary")
    def api_summary() -> Response:
        return jsonify(store().summary())

    @app.route("/api/images")
    def api_images() -> Response:
        return jsonify(store().images())

    @app.route("/api/scans")
    def api_scans() -> Response:
        return jsonify(
            store().scans(
                image=request.args.get("image"),
                since=request.args.get("since"),
                until=request.args.get("until"),
                limit=request.args.get("limit", default=100, type=int),
            )
        )

    @app.route("/api/findings/<scan_id>")
    def api_findings(scan_id: str) -> Response:
        return jsonify(
            store().findings(
                scan_id,
                severity=request.args.get("severity"),
                include_suppressed=request.args.get("suppressed") == "1",
            )
        )

    @app.route("/api/trend")
    def api_trend() -> Response:
        return jsonify(
            store().trend(
                image=request.args.get("image"),
                days=request.args.get("days", default=30, type=int),
            )
        )

    @app.route("/api/top-packages")
    def api_top_packages() -> Response:
        return jsonify(store().top_packages(limit=request.args.get("limit", default=10, type=int)))

    # -- ops -----------------------------------------------------------------

    @app.route("/metrics")
    def metrics() -> Response:
        try:
            exceptions = exception_store()
        except ExceptionError:
            exceptions = None
        payload = collect_store(
            store(), exceptions, warn_days=config.exceptions.warn_on_expiring_within_days
        )
        return Response(payload, mimetype="text/plain; version=0.0.4; charset=utf-8")

    @app.route("/healthz")
    def healthz() -> Response:
        try:
            store().summary()
            return jsonify({"status": "ok"})
        except Exception as exc:  # pragma: no cover - defensive
            return Response(f'{{"status":"error","detail":"{exc}"}}', status=503, mimetype="application/json")

    return app


app = None  # populated by `flask --app aegis.dashboard:build run` if needed


def build() -> Flask:  # pragma: no cover - entry point helper
    return create_app()
