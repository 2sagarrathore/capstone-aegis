"""Historical scan store (SQLite).

SQLite rather than Postgres on purpose: the whole tool has to be runnable
inside a CI container with no side services, and a single file both the CLI and
the dashboard open keeps the deployment cost at zero.  The schema is plain
enough to port to Postgres later -- see docs/ARCHITECTURE.md.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from .models import PolicyDecision, ScanResult, Vulnerability

log = logging.getLogger("aegis.storage")

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id           TEXT PRIMARY KEY,
    image             TEXT NOT NULL,
    image_digest      TEXT,
    image_size_bytes  INTEGER DEFAULT 0,
    scanned_at        TEXT NOT NULL,
    scanner           TEXT,
    scanner_version   TEXT,
    duration_seconds  REAL DEFAULT 0,
    os_family         TEXT,
    os_version        TEXT,
    total             INTEGER DEFAULT 0,
    critical          INTEGER DEFAULT 0,
    high              INTEGER DEFAULT 0,
    medium            INTEGER DEFAULT 0,
    low               INTEGER DEFAULT 0,
    unknown           INTEGER DEFAULT 0,
    fixable           INTEGER DEFAULT 0,
    suppressed        INTEGER DEFAULT 0,
    verdict           TEXT,
    reasons           TEXT,
    source            TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    scan_id           TEXT NOT NULL,
    vuln_id           TEXT NOT NULL,
    package           TEXT NOT NULL,
    installed_version TEXT NOT NULL,
    fixed_version     TEXT,
    severity          TEXT NOT NULL,
    target            TEXT,
    pkg_type          TEXT,
    cvss_score        REAL,
    primary_url       TEXT,
    title             TEXT,
    published_date    TEXT,
    suppressed        INTEGER DEFAULT 0,
    PRIMARY KEY (scan_id, vuln_id, package, installed_version),
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scans_image      ON scans(image, scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_time       ON scans(scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_sev     ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_vuln    ON findings(vuln_id);
CREATE INDEX IF NOT EXISTS idx_findings_package ON findings(package);
"""


@dataclass
class ScanDiff:
    """What changed between the previous scan of an image and this one.

    ``resolved`` and ``waived`` are kept apart deliberately: a finding that
    disappeared because the package was patched is not the same event as one
    that disappeared because somebody signed a waiver, and reporting the second
    as the first flatters the numbers.
    """

    introduced: list[Vulnerability]
    resolved: list[Vulnerability]
    unchanged_count: int
    previous_scan_id: str | None = None
    waived: list[Vulnerability] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.introduced or self.resolved or self.waived)

    def introduced_at_or_above(self, severity) -> list[Vulnerability]:
        return [v for v in self.introduced if v.severity >= severity]

    def to_dict(self) -> dict[str, Any]:
        return {
            "previous_scan_id": self.previous_scan_id,
            "introduced": [v.to_dict() for v in self.introduced],
            "resolved": [v.to_dict() for v in self.resolved],
            "waived": [v.to_dict() for v in self.waived],
            "unchanged_count": self.unchanged_count,
        }


class ScanStore:
    """Thin, typed wrapper over the SQLite file."""

    def __init__(self, path: str | Path = "aegis.db") -> None:
        self.path = Path(path)
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.path), timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self.connect() as conn:
            conn.executescript(SCHEMA)

    # -- writing -------------------------------------------------------------

    def record(
        self,
        result: ScanResult,
        decision: PolicyDecision | None = None,
        source: str = "cli",
    ) -> str:
        """Persist one scan plus its findings.  Idempotent on ``scan_id``."""
        counts = result.counts()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO scans (
                    scan_id, image, image_digest, image_size_bytes, scanned_at,
                    scanner, scanner_version, duration_seconds, os_family, os_version,
                    total, critical, high, medium, low, unknown, fixable, suppressed,
                    verdict, reasons, source
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    result.scan_id,
                    result.image,
                    result.image_digest,
                    result.image_size_bytes,
                    result.scanned_at,
                    result.scanner,
                    result.scanner_version,
                    result.duration_seconds,
                    result.os_family,
                    result.os_version,
                    result.total,
                    counts["CRITICAL"],
                    counts["HIGH"],
                    counts["MEDIUM"],
                    counts["LOW"],
                    counts["UNKNOWN"],
                    result.fixable_count(),
                    len(result.suppressed),
                    decision.verdict if decision else None,
                    json.dumps(decision.reasons) if decision else None,
                    source,
                ),
            )
            conn.execute("DELETE FROM findings WHERE scan_id = ?", (result.scan_id,))
            rows = [
                (
                    result.scan_id,
                    v.vuln_id,
                    v.package,
                    v.installed_version,
                    v.fixed_version,
                    v.severity.value,
                    v.target,
                    v.pkg_type,
                    v.cvss_score,
                    v.primary_url,
                    v.title,
                    v.published_date,
                    suppressed,
                )
                for suppressed, bucket in ((0, result.vulnerabilities), (1, result.suppressed))
                for v in bucket
            ]
            conn.executemany(
                """
                INSERT OR REPLACE INTO findings (
                    scan_id, vuln_id, package, installed_version, fixed_version,
                    severity, target, pkg_type, cvss_score, primary_url, title,
                    published_date, suppressed
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                rows,
            )
        log.debug("recorded scan %s for %s (%d findings)", result.scan_id, result.image, result.total)
        return result.scan_id

    def purge_older_than(self, days: int) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
        with self.connect() as conn:
            scan_ids = [
                row["scan_id"]
                for row in conn.execute("SELECT scan_id FROM scans WHERE scanned_at < ?", (cutoff,))
            ]
            conn.executemany("DELETE FROM findings WHERE scan_id = ?", [(s,) for s in scan_ids])
            conn.execute("DELETE FROM scans WHERE scanned_at < ?", (cutoff,))
        return len(scan_ids)

    # -- reading -------------------------------------------------------------

    def images(self) -> list[dict[str, Any]]:
        """Latest scan per image, newest first -- the dashboard's landing view."""
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT s.* FROM scans s
                JOIN (
                    SELECT image, MAX(scanned_at) AS latest
                    FROM scans GROUP BY image
                ) m ON s.image = m.image AND s.scanned_at = m.latest
                ORDER BY s.critical DESC, s.high DESC, s.image ASC
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def scans(
        self,
        image: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        clauses, params = [], []
        if image:
            clauses.append("image LIKE ?")
            params.append(image.replace("*", "%"))
        if since:
            clauses.append("scanned_at >= ?")
            params.append(since)
        if until:
            clauses.append("scanned_at <= ?")
            params.append(until)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        with self.connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM scans {where} ORDER BY scanned_at DESC LIMIT ?", params
            ).fetchall()
        return [dict(row) for row in rows]

    def latest_scan(self, image: str, before: str | None = None) -> dict[str, Any] | None:
        """Most recent scan of ``image``, optionally strictly older than ``before``.

        ``before`` is an ISO timestamp rather than a scan id on purpose: the
        pipeline diffs a *fresh* result that has not been written yet, so there
        is no id to look up.
        """
        with self.connect() as conn:
            if before:
                row = conn.execute(
                    """
                    SELECT * FROM scans
                    WHERE image = ? AND scanned_at < ?
                    ORDER BY scanned_at DESC LIMIT 1
                    """,
                    (image, before),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT * FROM scans WHERE image = ? ORDER BY scanned_at DESC LIMIT 1",
                    (image,),
                ).fetchone()
        return dict(row) if row else None

    def findings(
        self,
        scan_id: str,
        severity: str | None = None,
        include_suppressed: bool = False,
    ) -> list[dict[str, Any]]:
        clauses, params = ["scan_id = ?"], [scan_id]
        if not include_suppressed:
            clauses.append("suppressed = 0")
        if severity:
            clauses.append("severity = ?")
            params.append(severity.upper())
        with self.connect() as conn:
            rows = conn.execute(
                f"""
                SELECT * FROM findings WHERE {' AND '.join(clauses)}
                ORDER BY CASE severity
                    WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2
                    WHEN 'LOW' THEN 3 ELSE 4 END, package
                """,
                params,
            ).fetchall()
        return [dict(row) for row in rows]

    def _vulnerabilities_for(self, scan_id: str) -> dict[str, Vulnerability]:
        out: dict[str, Vulnerability] = {}
        for row in self.findings(scan_id, include_suppressed=False):
            vuln = Vulnerability.from_dict(row)
            out[vuln.fingerprint] = vuln
        return out

    def diff_with_previous(self, result: ScanResult) -> ScanDiff:
        """Compare a fresh result against the last stored scan of the same image."""
        previous = self.latest_scan(result.image, before=result.scanned_at)
        current = {v.fingerprint: v for v in result.vulnerabilities}
        if not previous:
            return ScanDiff(
                introduced=list(result.vulnerabilities), resolved=[], unchanged_count=0
            )
        prior = self._vulnerabilities_for(previous["scan_id"])
        suppressed = {v.fingerprint for v in result.suppressed}
        introduced = [v for key, v in current.items() if key not in prior]
        resolved = [
            v for key, v in prior.items() if key not in current and key not in suppressed
        ]
        waived = [v for key, v in prior.items() if key not in current and key in suppressed]
        unchanged = len(set(current) & set(prior))
        return ScanDiff(
            introduced=introduced,
            resolved=resolved,
            waived=waived,
            unchanged_count=unchanged,
            previous_scan_id=previous["scan_id"],
        )

    # -- aggregates used by the dashboard ------------------------------------

    def trend(self, image: str | None = None, days: int = 30) -> list[dict[str, Any]]:
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
        clauses, params = ["scanned_at >= ?"], [since]
        if image:
            clauses.append("image LIKE ?")
            params.append(image.replace("*", "%"))
        # One data point per image per day -- the *last* scan of that day. Summing
        # every scan would make a day with three rebuilds of one image look three
        # times worse than a day with one.
        with self.connect() as conn:
            rows = conn.execute(
                f"""
                WITH daily AS (
                    SELECT image,
                           substr(scanned_at, 1, 10) AS day,
                           MAX(scanned_at) AS latest
                    FROM scans WHERE {' AND '.join(clauses)}
                    GROUP BY image, day
                )
                SELECT d.day AS day,
                       SUM(s.critical) AS critical, SUM(s.high) AS high,
                       SUM(s.medium) AS medium, SUM(s.low) AS low,
                       SUM(s.total) AS total, COUNT(*) AS scans
                FROM scans s
                JOIN daily d ON s.image = d.image AND s.scanned_at = d.latest
                GROUP BY d.day ORDER BY d.day ASC
                """,
                params,
            ).fetchall()
        return [dict(row) for row in rows]

    def top_packages(self, limit: int = 10, days: int = 30) -> list[dict[str, Any]]:
        """Most frequently flagged packages across the latest scan of each image."""
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
        with self.connect() as conn:
            rows = conn.execute(
                """
                WITH latest AS (
                    SELECT s.scan_id FROM scans s
                    JOIN (SELECT image, MAX(scanned_at) AS latest FROM scans
                          WHERE scanned_at >= ? GROUP BY image) m
                      ON s.image = m.image AND s.scanned_at = m.latest
                )
                SELECT f.package,
                       COUNT(*) AS findings,
                       SUM(CASE WHEN f.severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical,
                       SUM(CASE WHEN f.severity = 'HIGH' THEN 1 ELSE 0 END) AS high,
                       SUM(CASE WHEN f.severity = 'MEDIUM' THEN 1 ELSE 0 END) AS medium,
                       SUM(CASE WHEN f.severity = 'LOW' THEN 1 ELSE 0 END) AS low,
                       SUM(CASE WHEN f.severity = 'UNKNOWN' THEN 1 ELSE 0 END) AS unknown,
                       SUM(CASE WHEN f.fixed_version != '' THEN 1 ELSE 0 END) AS fixable
                FROM findings f
                JOIN latest l ON f.scan_id = l.scan_id
                WHERE f.suppressed = 0
                GROUP BY f.package
                ORDER BY findings DESC, critical DESC, high DESC
                LIMIT ?
                """,
                (since, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def summary(self) -> dict[str, Any]:
        latest = self.images()
        with self.connect() as conn:
            total_scans = conn.execute("SELECT COUNT(*) AS c FROM scans").fetchone()["c"]
        return {
            "images_tracked": len(latest),
            "total_scans": total_scans,
            "critical": sum(row["critical"] for row in latest),
            "high": sum(row["high"] for row in latest),
            "medium": sum(row["medium"] for row in latest),
            "low": sum(row["low"] for row in latest),
            "fixable": sum(row["fixable"] for row in latest),
            "suppressed": sum(row["suppressed"] for row in latest),
            "failing_images": sum(1 for row in latest if row["verdict"] == "FAIL"),
        }

    def stale_images(self, hours: int = 24) -> list[dict[str, Any]]:
        """Images whose most recent scan is older than ``hours`` -- rescan candidates."""
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(timespec="seconds")
        return [row for row in self.images() if row["scanned_at"] < cutoff]
