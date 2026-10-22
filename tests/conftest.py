import json
from datetime import date, timedelta
from pathlib import Path

import pytest

from aegis.config import AegisConfig
from aegis.models import ScanResult, Severity, Vulnerability
from aegis.scanner import TrivyScanner
from aegis.storage import ScanStore

FIXTURE = Path(__file__).parent / "fixtures" / "trivy_python39.json"


@pytest.fixture
def trivy_raw() -> dict:
    """Real (trimmed) Trivy output, captured from `trivy image python:3.9-slim`."""
    with open(FIXTURE, encoding="utf-8") as handle:
        return json.load(handle)


@pytest.fixture
def config() -> AegisConfig:
    return AegisConfig()


@pytest.fixture
def parsed(trivy_raw, config) -> ScanResult:
    return TrivyScanner(config)._parse("python:3.9-slim", trivy_raw)


@pytest.fixture
def store(tmp_path) -> ScanStore:
    return ScanStore(tmp_path / "test.db")


def make_vuln(
    vuln_id="CVE-2024-0001",
    package="openssl",
    severity=Severity.HIGH,
    fixed_version="1.1.1w",
    installed_version="1.1.1k",
) -> Vulnerability:
    return Vulnerability(
        vuln_id=vuln_id,
        package=package,
        installed_version=installed_version,
        severity=severity,
        fixed_version=fixed_version,
    )


def make_result(image="app:1.0", vulns=None) -> ScanResult:
    return ScanResult(
        image=image,
        scanned_at=ScanResult.now(),
        vulnerabilities=list(vulns or []),
    )


@pytest.fixture
def future() -> date:
    return date.today() + timedelta(days=30)


@pytest.fixture
def past() -> date:
    return date.today() - timedelta(days=1)
