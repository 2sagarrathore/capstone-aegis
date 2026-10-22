"""Scanner engine wrappers.

Only this module knows what the underlying scanner's output looks like.  It
turns that into :class:`~aegis.models.ScanResult` and nothing else in the code
base parses scanner JSON.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from .config import AegisConfig
from .models import ScanResult, Severity, Vulnerability

log = logging.getLogger("aegis.scanner")

# Substrings that mark a failure as worth retrying rather than reporting.
TRANSIENT_MARKERS = (
    "i/o timeout",
    "connection refused",
    "connection reset",
    "unexpected eof",
    "temporary failure",
    "too many requests",
    "toomanyrequests",
    "timeout exceeded",
    "database download",
    "failed to download",
    "context deadline exceeded",
    "no such host",
    "503 service unavailable",
    "502 bad gateway",
    "tls handshake timeout",
)

NOT_FOUND_MARKERS = (
    "manifest unknown",
    "no such image",
    "not found",
    "does not exist",
    "unauthorized",
    "repository name must",
)


class ScannerError(RuntimeError):
    """Scanning failed in a way the caller should surface."""


class ScannerNotInstalled(ScannerError):
    """The scanner binary is missing from PATH."""


class ImageNotFound(ScannerError):
    """The image reference could not be resolved or pulled."""


class TransientScannerError(ScannerError):
    """A failure that is worth retrying (network, registry rate limit, DB update)."""


def _is_transient(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in TRANSIENT_MARKERS)


def _is_not_found(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in NOT_FOUND_MARKERS)


class Scanner(ABC):
    """Interface every engine implementation satisfies."""

    name = "scanner"

    @abstractmethod
    def scan(self, image: str) -> ScanResult:  # pragma: no cover - interface
        ...

    @abstractmethod
    def version(self) -> str:  # pragma: no cover - interface
        ...


class TrivyScanner(Scanner):
    """Runs ``trivy image`` and normalizes its JSON report."""

    name = "trivy"

    def __init__(self, config: AegisConfig, binary: str = "trivy") -> None:
        self.config = config
        self.binary = binary
        self._version: str | None = None

    # -- public API ----------------------------------------------------------

    def version(self) -> str:
        if self._version is not None:
            return self._version
        self._require_binary()
        try:
            out = subprocess.run(
                [self.binary, "--version", "--format", "json"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            payload = json.loads(out.stdout)
            self._version = str(payload.get("Version", "unknown"))
        except (json.JSONDecodeError, subprocess.SubprocessError, OSError):
            self._version = "unknown"
        return self._version

    def scan(self, image: str) -> ScanResult:
        """Scan ``image``, retrying transient failures with linear backoff."""
        self._require_binary()
        attempts = max(1, self.config.scanner.retries + 1)
        last_error: Exception | None = None

        for attempt in range(1, attempts + 1):
            started = time.monotonic()
            try:
                raw = self._run_trivy(image)
                result = self._parse(image, raw)
                result.duration_seconds = time.monotonic() - started
                result.scanner_version = self.version()
                self._enrich_from_docker(result)
                return result
            except TransientScannerError as exc:
                last_error = exc
                if attempt == attempts:
                    break
                backoff = self.config.scanner.retry_backoff_seconds * attempt
                log.warning(
                    "transient scan failure for %s (attempt %d/%d): %s -- retrying in %.1fs",
                    image,
                    attempt,
                    attempts,
                    exc,
                    backoff,
                )
                time.sleep(backoff)

        raise ScannerError(
            f"scan of {image} failed after {attempts} attempt(s): {last_error}"
        ) from last_error

    # -- internals -----------------------------------------------------------

    def _require_binary(self) -> None:
        if shutil.which(self.binary) is None:
            raise ScannerNotInstalled(
                f"'{self.binary}' not found on PATH. Install it with "
                "`brew install trivy` or see docs/SETUP.md."
            )

    def build_command(self, image: str) -> list[str]:
        cfg = self.config.scanner
        cmd = [
            self.binary,
            "image",
            "--format",
            "json",
            "--quiet",
            "--timeout",
            f"{cfg.timeout_seconds}s",
        ]
        if cfg.severities:
            cmd += ["--severity", ",".join(s.upper() for s in cfg.severities)]
        if cfg.scanners:
            cmd += ["--scanners", ",".join(cfg.scanners)]
        if cfg.ignore_unfixed:
            cmd.append("--ignore-unfixed")
        if cfg.cache_dir:
            cmd += ["--cache-dir", str(Path(cfg.cache_dir).expanduser())]
        if cfg.skip_db_update or cfg.offline:
            cmd.append("--skip-db-update")
        if cfg.offline:
            cmd.append("--offline-scan")
        if cfg.db_repository:
            cmd += ["--db-repository", cfg.db_repository]
        if cfg.platform:
            cmd += ["--platform", cfg.platform]
        cmd.append(image)
        return cmd

    def _run_trivy(self, image: str) -> dict[str, Any]:
        cmd = self.build_command(image)
        log.debug("running: %s", " ".join(cmd))
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.scanner.timeout_seconds + 60,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise TransientScannerError(
                f"trivy timed out after {self.config.scanner.timeout_seconds}s"
            ) from exc
        except OSError as exc:  # pragma: no cover - defensive
            raise ScannerError(f"could not execute trivy: {exc}") from exc

        if proc.returncode != 0:
            stderr = (proc.stderr or "").strip()
            if _is_transient(stderr):
                raise TransientScannerError(stderr.splitlines()[-1] if stderr else "unknown")
            if _is_not_found(stderr):
                raise ImageNotFound(f"cannot resolve image '{image}': {stderr}")
            raise ScannerError(f"trivy exited {proc.returncode}: {stderr}")

        if not proc.stdout.strip():
            raise ScannerError("trivy produced no output")

        try:
            return json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise ScannerError(f"could not parse trivy JSON output: {exc}") from exc

    def _parse(self, image: str, raw: dict[str, Any]) -> ScanResult:
        metadata = raw.get("Metadata") or {}
        os_info = metadata.get("OS") or {}
        digests = metadata.get("RepoDigests") or []

        result = ScanResult(
            image=raw.get("ArtifactName") or image,
            scanned_at=ScanResult.now(),
            image_digest=digests[0] if digests else "",
            image_size_bytes=int(metadata.get("Size") or 0),
            os_family=os_info.get("Family", ""),
            os_version=os_info.get("Name", ""),
            scanner=self.name,
        )

        seen: set[str] = set()
        for section in raw.get("Results") or []:
            target = section.get("Target", "")
            pkg_type = section.get("Type", "")
            for item in section.get("Vulnerabilities") or []:
                vuln = self._to_vulnerability(item, target, pkg_type)
                if vuln.fingerprint in seen:
                    continue  # same CVE can appear in several targets of one image
                seen.add(vuln.fingerprint)
                result.vulnerabilities.append(vuln)
        return result

    @staticmethod
    def _to_vulnerability(item: dict[str, Any], target: str, pkg_type: str) -> Vulnerability:
        cvss = item.get("CVSS") or {}
        score: float | None = None
        for source in ("nvd", "redhat", "ghsa"):
            entry = cvss.get(source) or {}
            value = entry.get("V3Score") or entry.get("V2Score")
            if value is not None:
                score = float(value)
                break

        return Vulnerability(
            vuln_id=item.get("VulnerabilityID", "UNKNOWN"),
            package=item.get("PkgName", ""),
            installed_version=item.get("InstalledVersion", ""),
            severity=Severity.parse(item.get("Severity")),
            title=(item.get("Title") or item.get("Description") or "")[:300],
            fixed_version=item.get("FixedVersion", "") or "",
            target=target,
            pkg_type=pkg_type,
            primary_url=item.get("PrimaryURL", ""),
            cvss_score=score,
            published_date=(item.get("PublishedDate") or "")[:10],
        )

    @staticmethod
    def _enrich_from_docker(result: ScanResult) -> None:
        """Fill in size/digest from the local Docker daemon when Trivy omits them."""
        if result.image_size_bytes and result.image_digest:
            return
        if shutil.which("docker") is None:
            return
        try:
            proc = subprocess.run(
                [
                    "docker",
                    "image",
                    "inspect",
                    result.image,
                    "--format",
                    "{{.Size}}|{{if .RepoDigests}}{{index .RepoDigests 0}}{{end}}",
                ],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        except (subprocess.SubprocessError, OSError):
            return
        if proc.returncode != 0 or "|" not in proc.stdout:
            return
        size, _, digest = proc.stdout.strip().partition("|")
        if not result.image_size_bytes and size.isdigit():
            result.image_size_bytes = int(size)
        if not result.image_digest and digest:
            result.image_digest = digest


ENGINES: dict[str, type[Scanner]] = {"trivy": TrivyScanner}


def get_scanner(config: AegisConfig) -> Scanner:
    engine = (config.scanner.engine or "trivy").lower()
    if engine not in ENGINES:
        raise ScannerError(
            f"unsupported scanner engine '{engine}'. Available: {', '.join(sorted(ENGINES))}"
        )
    return ENGINES[engine](config)
