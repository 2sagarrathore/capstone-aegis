"""Retry / error-handling behaviour, with the trivy subprocess stubbed out."""

import json
import subprocess
from pathlib import Path

import pytest

from aegis.config import AegisConfig
from aegis.scanner import (
    ImageNotFound,
    ScannerError,
    TransientScannerError,
    TrivyScanner,
)

FIXTURE = Path(__file__).parent / "fixtures" / "trivy_python39.json"


class FakeCompleted:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


@pytest.fixture
def scanner(monkeypatch):
    config = AegisConfig()
    config.scanner.retries = 2
    config.scanner.retry_backoff_seconds = 0  # keep the tests fast
    scanner = TrivyScanner(config)
    monkeypatch.setattr("aegis.scanner.shutil.which", lambda name: "/usr/local/bin/trivy")
    monkeypatch.setattr(scanner, "version", lambda: "0.76.1")
    monkeypatch.setattr(TrivyScanner, "_enrich_from_docker", staticmethod(lambda result: None))
    return scanner


def stub_runs(monkeypatch, responses):
    """Feed `subprocess.run` a scripted sequence of results/exceptions."""
    calls = {"n": 0}

    def fake_run(*args, **kwargs):
        index = min(calls["n"], len(responses) - 1)
        calls["n"] += 1
        response = responses[index]
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr("aegis.scanner.subprocess.run", fake_run)
    return calls


def test_transient_failure_is_retried_then_succeeds(scanner, monkeypatch):
    good = FakeCompleted(stdout=FIXTURE.read_text())
    calls = stub_runs(monkeypatch, [
        FakeCompleted(returncode=1, stderr="Get https://ghcr.io/v2/: i/o timeout"),
        good,
    ])
    result = scanner.scan("python:3.9-slim")
    assert calls["n"] == 2
    assert result.total == 18


def test_retries_are_bounded(scanner, monkeypatch):
    calls = stub_runs(monkeypatch, [
        FakeCompleted(returncode=1, stderr="TOOMANYREQUESTS: rate limited")
    ])
    with pytest.raises(ScannerError, match="after 3 attempt"):
        scanner.scan("app:1")
    assert calls["n"] == 3  # 1 attempt + 2 retries


def test_missing_image_is_not_retried(scanner, monkeypatch):
    calls = stub_runs(monkeypatch, [
        FakeCompleted(returncode=1, stderr="MANIFEST_UNKNOWN: manifest unknown")
    ])
    with pytest.raises(ImageNotFound, match="cannot resolve image"):
        scanner.scan("nope:1")
    assert calls["n"] == 1


def test_timeout_is_treated_as_transient(scanner, monkeypatch):
    stub_runs(monkeypatch, [subprocess.TimeoutExpired(cmd="trivy", timeout=1)])
    with pytest.raises(ScannerError, match="after 3 attempt"):
        scanner.scan("app:1")


def test_unparseable_output_is_a_hard_error(scanner, monkeypatch):
    stub_runs(monkeypatch, [FakeCompleted(stdout="not json at all")])
    with pytest.raises(ScannerError, match="could not parse"):
        scanner.scan("app:1")


def test_empty_output_is_a_hard_error(scanner, monkeypatch):
    stub_runs(monkeypatch, [FakeCompleted(stdout="   ")])
    with pytest.raises(ScannerError, match="no output"):
        scanner.scan("app:1")


def test_scan_records_duration_and_version(scanner, monkeypatch):
    stub_runs(monkeypatch, [FakeCompleted(stdout=FIXTURE.read_text())])
    result = scanner.scan("python:3.9-slim")
    assert result.duration_seconds >= 0
    assert result.scanner_version == "0.76.1"
    assert result.scanner == "trivy"


def test_result_with_no_vulnerabilities_section(scanner, monkeypatch):
    payload = {"ArtifactName": "clean:1", "Results": [{"Target": "clean", "Type": "debian"}]}
    stub_runs(monkeypatch, [FakeCompleted(stdout=json.dumps(payload))])
    assert scanner.scan("clean:1").total == 0
