"""Approved-vulnerability exceptions (the allowlist).

Real pipelines need an escape hatch: a CVE with no upstream fix, or one that is
not reachable in the deployed configuration, should not block every build
forever.  Every exception here is time-boxed -- an entry without an expiry date
is rejected -- so the allowlist cannot quietly become permanent.
"""

from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any, Iterable

import yaml

from .models import ScanResult, Vulnerability

log = logging.getLogger("aegis.exceptions")


def _parse_date(value: Any) -> date | None:
    if value in (None, ""):
        return None
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()
    try:
        return datetime.strptime(str(value).strip()[:10], "%Y-%m-%d").date()
    except ValueError:
        return None


class ExceptionError(ValueError):
    """An exception entry is malformed."""


@dataclass
class VulnerabilityException:
    """One approved exception.

    ``package`` and ``image`` are shell-style globs; ``*`` (the default) matches
    anything, so ``id: CVE-2024-1 / image: internal/*`` scopes a waiver to one
    repository.
    """

    vuln_id: str
    reason: str
    expires: date
    package: str = "*"
    image: str = "*"
    approved_by: str = ""
    created: date = field(default_factory=date.today)
    ticket: str = ""

    def is_expired(self, on: date | None = None) -> bool:
        return self.expires < (on or date.today())

    def days_remaining(self, on: date | None = None) -> int:
        return (self.expires - (on or date.today())).days

    def matches(self, vuln: Vulnerability, image: str, on: date | None = None) -> bool:
        if self.is_expired(on):
            return False
        if self.vuln_id != "*" and self.vuln_id.upper() != vuln.vuln_id.upper():
            return False
        if not fnmatch.fnmatch(vuln.package.lower(), self.package.lower()):
            return False
        return fnmatch.fnmatch(image.lower(), self.image.lower())

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.vuln_id,
            "package": self.package,
            "image": self.image,
            "reason": self.reason,
            "approved_by": self.approved_by,
            "ticket": self.ticket,
            "created": self.created.isoformat(),
            "expires": self.expires.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VulnerabilityException":
        vuln_id = str(data.get("id") or data.get("vuln_id") or "").strip()
        if not vuln_id:
            raise ExceptionError("exception entry is missing 'id'")
        reason = str(data.get("reason") or "").strip()
        if not reason:
            raise ExceptionError(f"exception {vuln_id} is missing 'reason'")
        expires = _parse_date(data.get("expires"))
        if expires is None:
            raise ExceptionError(
                f"exception {vuln_id} needs an 'expires' date (YYYY-MM-DD); "
                "permanent waivers are not allowed"
            )
        return cls(
            vuln_id=vuln_id,
            reason=reason,
            expires=expires,
            package=str(data.get("package") or "*"),
            image=str(data.get("image") or "*"),
            approved_by=str(data.get("approved_by") or ""),
            created=_parse_date(data.get("created")) or date.today(),
            ticket=str(data.get("ticket") or ""),
        )


class ExceptionStore:
    """Loads, queries and persists the exception list."""

    def __init__(self, entries: list[VulnerabilityException] | None = None, path: Path | None = None):
        self.entries = entries or []
        self.path = path

    # -- loading / saving ----------------------------------------------------

    @classmethod
    def load(cls, path: str | Path | None) -> "ExceptionStore":
        if path is None:
            return cls()
        file_path = Path(path)
        if not file_path.exists():
            log.debug("no exceptions file at %s -- starting empty", file_path)
            return cls(path=file_path)
        with open(file_path, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        raw_entries = data.get("exceptions") or []
        entries: list[VulnerabilityException] = []
        for raw in raw_entries:
            entries.append(VulnerabilityException.from_dict(raw))
        log.debug("loaded %d exception(s) from %s", len(entries), file_path)
        return cls(entries=entries, path=file_path)

    def save(self, path: str | Path | None = None) -> Path:
        target = Path(path or self.path or "exceptions.yml")
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "exceptions": [entry.to_dict() for entry in self.entries],
        }
        with open(target, "w", encoding="utf-8") as handle:
            yaml.safe_dump(payload, handle, sort_keys=False)
        self.path = target
        return target

    # -- mutation ------------------------------------------------------------

    def add(
        self,
        vuln_id: str,
        reason: str,
        *,
        expires: date | None = None,
        default_expiry_days: int = 90,
        package: str = "*",
        image: str = "*",
        approved_by: str = "",
        ticket: str = "",
    ) -> VulnerabilityException:
        entry = VulnerabilityException(
            vuln_id=vuln_id,
            reason=reason,
            expires=expires or (date.today() + timedelta(days=default_expiry_days)),
            package=package,
            image=image,
            approved_by=approved_by,
            ticket=ticket,
        )
        self.entries = [
            existing
            for existing in self.entries
            if not (
                existing.vuln_id.upper() == entry.vuln_id.upper()
                and existing.package == entry.package
                and existing.image == entry.image
            )
        ]
        self.entries.append(entry)
        return entry

    def remove(self, vuln_id: str, image: str = "*", package: str = "*") -> int:
        before = len(self.entries)
        self.entries = [
            entry
            for entry in self.entries
            if not (
                entry.vuln_id.upper() == vuln_id.upper()
                and (image == "*" or entry.image == image)
                and (package == "*" or entry.package == package)
            )
        ]
        return before - len(self.entries)

    def prune_expired(self, on: date | None = None) -> list[VulnerabilityException]:
        expired = [entry for entry in self.entries if entry.is_expired(on)]
        self.entries = [entry for entry in self.entries if not entry.is_expired(on)]
        return expired

    # -- querying ------------------------------------------------------------

    def expired(self, on: date | None = None) -> list[VulnerabilityException]:
        return [entry for entry in self.entries if entry.is_expired(on)]

    def expiring_within(self, days: int, on: date | None = None) -> list[VulnerabilityException]:
        return [
            entry
            for entry in self.entries
            if not entry.is_expired(on) and entry.days_remaining(on) <= days
        ]

    def match(
        self, vuln: Vulnerability, image: str, on: date | None = None
    ) -> VulnerabilityException | None:
        for entry in self.entries:
            if entry.matches(vuln, image, on):
                return entry
        return None

    def apply(self, result: ScanResult, on: date | None = None) -> ScanResult:
        """Move suppressed findings out of ``vulnerabilities`` and into ``suppressed``.

        Mutates and returns ``result`` so the gate, reports and metrics all see
        the same post-exception view.
        """
        active: list[Vulnerability] = []
        suppressed: list[Vulnerability] = list(result.suppressed)
        for vuln in result.vulnerabilities:
            entry = self.match(vuln, result.image, on)
            if entry:
                log.info(
                    "suppressing %s (%s) in %s -- %s (expires %s)",
                    vuln.vuln_id,
                    vuln.package,
                    result.image,
                    entry.reason,
                    entry.expires.isoformat(),
                )
                suppressed.append(vuln)
            else:
                active.append(vuln)
        result.vulnerabilities = active
        result.suppressed = suppressed
        return result

    def __len__(self) -> int:
        return len(self.entries)

    def __iter__(self) -> Iterable[VulnerabilityException]:
        return iter(self.entries)
