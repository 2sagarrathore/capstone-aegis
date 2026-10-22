"""Normalized data model for scan results.

Trivy is the default scanner engine, but nothing outside ``scanner.py`` is
allowed to depend on its JSON shape -- everything downstream (policy, reports,
storage, metrics) works against the types declared here.  That keeps the door
open for Clair or Grype as an alternative engine later.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable


class Severity(str, Enum):
    """CVE severity, ordered from least to most urgent."""

    UNKNOWN = "UNKNOWN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER.index(self)

    def __ge__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.rank >= other.rank

    def __gt__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.rank > other.rank

    def __le__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.rank <= other.rank

    def __lt__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.rank < other.rank

    @classmethod
    def parse(cls, raw: str | None) -> "Severity":
        if not raw:
            return cls.UNKNOWN
        try:
            return cls(raw.strip().upper())
        except ValueError:
            return cls.UNKNOWN


_SEVERITY_ORDER = [
    Severity.UNKNOWN,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]

ALL_SEVERITIES = [s for s in _SEVERITY_ORDER]


@dataclass(frozen=True)
class Vulnerability:
    """A single finding against one package inside an image layer."""

    vuln_id: str
    package: str
    installed_version: str
    severity: Severity
    title: str = ""
    fixed_version: str = ""
    target: str = ""
    pkg_type: str = ""
    primary_url: str = ""
    cvss_score: float | None = None
    published_date: str = ""

    @property
    def fixable(self) -> bool:
        return bool(self.fixed_version)

    @property
    def fingerprint(self) -> str:
        """Stable identity used for de-duplication and exception matching."""
        return f"{self.vuln_id}:{self.package}:{self.installed_version}"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["fixable"] = self.fixable
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Vulnerability":
        payload = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        payload["severity"] = Severity.parse(payload.get("severity"))
        return cls(**payload)


@dataclass
class ScanResult:
    """Everything one scan of one image produced."""

    image: str
    scanned_at: str
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    image_digest: str = ""
    image_size_bytes: int = 0
    os_family: str = ""
    os_version: str = ""
    scanner: str = "trivy"
    scanner_version: str = ""
    duration_seconds: float = 0.0
    suppressed: list[Vulnerability] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @staticmethod
    def now() -> str:
        # Millisecond resolution: two scans of the same image inside one second
        # are ordinary (a rescan loop, a matrix build), and with second
        # resolution the second one cannot find the first as its predecessor.
        return datetime.now(timezone.utc).isoformat(timespec="milliseconds")

    @property
    def scan_id(self) -> str:
        raw = f"{self.image}|{self.scanned_at}|{self.image_digest}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @property
    def total(self) -> int:
        return len(self.vulnerabilities)

    def counts(self) -> dict[str, int]:
        """Severity histogram over *active* (non-suppressed) findings."""
        counts = {s.value: 0 for s in ALL_SEVERITIES}
        for vuln in self.vulnerabilities:
            counts[vuln.severity.value] += 1
        return counts

    def count_at_or_above(self, floor: Severity) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity >= floor)

    def fixable_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.fixable)

    def by_severity(self) -> dict[str, list[Vulnerability]]:
        buckets: dict[str, list[Vulnerability]] = {s.value: [] for s in ALL_SEVERITIES}
        for vuln in self.vulnerabilities:
            buckets[vuln.severity.value].append(vuln)
        return buckets

    def sorted_vulnerabilities(self) -> list[Vulnerability]:
        return sorted(
            self.vulnerabilities,
            key=lambda v: (-v.severity.rank, not v.fixable, v.package, v.vuln_id),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "image": self.image,
            "image_digest": self.image_digest,
            "image_size_bytes": self.image_size_bytes,
            "scanned_at": self.scanned_at,
            "scanner": self.scanner,
            "scanner_version": self.scanner_version,
            "duration_seconds": round(self.duration_seconds, 3),
            "os": {"family": self.os_family, "version": self.os_version},
            "summary": {
                "total": self.total,
                "fixable": self.fixable_count(),
                "suppressed": len(self.suppressed),
                **self.counts(),
            },
            "vulnerabilities": [v.to_dict() for v in self.sorted_vulnerabilities()],
            "suppressed_vulnerabilities": [v.to_dict() for v in self.suppressed],
            "errors": self.errors,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanResult":
        return cls(
            image=data["image"],
            scanned_at=data["scanned_at"],
            vulnerabilities=[Vulnerability.from_dict(v) for v in data.get("vulnerabilities", [])],
            image_digest=data.get("image_digest", ""),
            image_size_bytes=data.get("image_size_bytes", 0),
            os_family=data.get("os", {}).get("family", ""),
            os_version=data.get("os", {}).get("version", ""),
            scanner=data.get("scanner", "trivy"),
            scanner_version=data.get("scanner_version", ""),
            duration_seconds=data.get("duration_seconds", 0.0),
            suppressed=[
                Vulnerability.from_dict(v) for v in data.get("suppressed_vulnerabilities", [])
            ],
            errors=data.get("errors", []),
        )


@dataclass
class PolicyDecision:
    """Outcome of evaluating a :class:`ScanResult` against the gate policy."""

    passed: bool
    reasons: list[str] = field(default_factory=list)
    breached_severities: list[str] = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        return 0 if self.passed else 1

    @property
    def verdict(self) -> str:
        return "PASS" if self.passed else "FAIL"

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "verdict": self.verdict,
            "reasons": self.reasons,
            "breached_severities": self.breached_severities,
        }


def merge_counts(results: Iterable[ScanResult]) -> dict[str, int]:
    totals = {s.value: 0 for s in ALL_SEVERITIES}
    for result in results:
        for severity, count in result.counts().items():
            totals[severity] += count
    return totals
