"""Parser tests run against real Trivy output captured in tests/fixtures."""

import pytest

from aegis.config import AegisConfig
from aegis.models import Severity
from aegis.scanner import (
    ScannerError,
    ScannerNotInstalled,
    TrivyScanner,
    _is_not_found,
    _is_transient,
    get_scanner,
)


def test_parses_metadata(parsed):
    assert parsed.image == "python:3.9-slim"
    assert parsed.os_family == "debian"
    assert parsed.image_digest.startswith("python@sha256:")
    assert parsed.image_size_bytes > 0


def test_parses_findings(parsed):
    assert parsed.total == 18
    assert parsed.counts()["CRITICAL"] >= 1
    assert all(v.vuln_id.startswith("CVE-") or v.vuln_id for v in parsed.vulnerabilities)


def test_cvss_score_is_extracted(parsed):
    scored = [v for v in parsed.vulnerabilities if v.cvss_score is not None]
    assert scored, "expected at least one finding with a CVSS score"
    assert all(0 <= v.cvss_score <= 10 for v in scored)


def test_duplicate_cve_across_targets_is_counted_once(trivy_raw):
    """The same CVE can appear under several targets of one image."""
    sections = trivy_raw["Results"]
    first = sections[0]["Vulnerabilities"][0]
    sections[0]["Vulnerabilities"].append(dict(first))
    result = TrivyScanner(AegisConfig())._parse("python:3.9-slim", trivy_raw)
    assert result.total == 18


def test_build_command_reflects_config():
    config = AegisConfig()
    config.scanner.ignore_unfixed = True
    config.scanner.offline = True
    config.scanner.severities = ["HIGH", "CRITICAL"]
    cmd = TrivyScanner(config).build_command("app:1")
    assert "--ignore-unfixed" in cmd
    assert "--offline-scan" in cmd
    assert "--skip-db-update" in cmd
    assert cmd[cmd.index("--severity") + 1] == "HIGH,CRITICAL"
    assert cmd[-1] == "app:1"


def test_transient_and_not_found_classification():
    assert _is_transient("Get https://ghcr.io: i/o timeout")
    assert _is_transient("TOOMANYREQUESTS: retry later")
    assert not _is_transient("MANIFEST_UNKNOWN: manifest unknown")
    assert _is_not_found("MANIFEST_UNKNOWN: manifest unknown")


def test_missing_binary_is_reported_clearly():
    scanner = TrivyScanner(AegisConfig(), binary="definitely-not-installed-xyz")
    with pytest.raises(ScannerNotInstalled, match="not found on PATH"):
        scanner.scan("app:1")


def test_unknown_engine_rejected():
    config = AegisConfig()
    config.scanner.engine = "nessus"
    with pytest.raises(ScannerError, match="unsupported scanner engine"):
        get_scanner(config)
