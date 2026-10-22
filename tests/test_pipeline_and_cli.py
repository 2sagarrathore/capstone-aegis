"""End-to-end tests with a stubbed scanner engine (no Trivy, no network)."""

import json

import pytest

from aegis.config import AegisConfig
from aegis.models import ScanResult, Severity
from aegis.pipeline import run_many, run_scan
from aegis.scanner import Scanner, ScannerError
from aegis.storage import ScanStore

from .conftest import make_vuln


class FakeScanner(Scanner):
    name = "fake"

    def __init__(self, vulns=None, fail_with=None):
        self.vulns = vulns or []
        self.fail_with = fail_with
        self.calls = []

    def version(self):
        return "0.0.0-test"

    def scan(self, image):
        self.calls.append(image)
        if self.fail_with:
            raise self.fail_with
        return ScanResult(
            image=image,
            scanned_at=ScanResult.now(),
            vulnerabilities=list(self.vulns),
            scanner=self.name,
            os_family="debian",
        )


@pytest.fixture
def config(tmp_path):
    config = AegisConfig()
    config.storage.database = str(tmp_path / "aegis.db")
    config.reporting.output_dir = str(tmp_path / "reports")
    config.exceptions.file = str(tmp_path / "exceptions.yml")
    config.metrics.textfile_path = str(tmp_path / "metrics.prom")
    return config


def test_clean_image_passes_and_writes_reports(config):
    outcome = run_scan("app:1", config, scanner=FakeScanner(), send_notifications=False)
    assert outcome.ok
    assert outcome.decision.verdict == "PASS"
    assert outcome.reports["json"].exists()
    assert outcome.reports["html"].exists()


def test_critical_finding_fails_the_gate(config):
    scanner = FakeScanner([make_vuln(severity=Severity.CRITICAL)])
    outcome = run_scan("app:1", config, scanner=scanner, send_notifications=False)
    assert not outcome.decision.passed
    assert outcome.decision.exit_code == 1


def test_results_are_persisted_and_diffed(config):
    first = FakeScanner([make_vuln("CVE-A"), make_vuln("CVE-B")])
    run_scan("app:1", config, scanner=first, send_notifications=False)

    second = FakeScanner([make_vuln("CVE-B"), make_vuln("CVE-C")])
    outcome = run_scan("app:1", config, scanner=second, send_notifications=False)

    assert [v.vuln_id for v in outcome.diff.introduced] == ["CVE-C"]
    assert [v.vuln_id for v in outcome.diff.resolved] == ["CVE-A"]
    assert len(ScanStore(config.storage.database).scans()) == 2


def test_exceptions_suppress_findings_before_the_gate(config, tmp_path):
    (tmp_path / "exceptions.yml").write_text(
        "version: 1\n"
        "exceptions:\n"
        "  - id: CVE-2024-0001\n"
        "    reason: not reachable\n"
        "    expires: 2099-01-01\n"
    )
    scanner = FakeScanner([make_vuln("CVE-2024-0001", severity=Severity.CRITICAL)])
    outcome = run_scan("app:1", config, scanner=scanner, send_notifications=False)
    assert outcome.decision.passed
    assert len(outcome.result.suppressed) == 1


def test_metrics_file_is_written_per_image(config, tmp_path):
    run_scan("registry/app:1", config, scanner=FakeScanner(), send_notifications=False)
    written = list(tmp_path.glob("metrics_*.prom"))
    assert len(written) == 1
    assert "aegis_vulnerabilities" in written[0].read_text()


def test_run_many_continues_past_a_failing_image(config):
    good = FakeScanner()
    outcomes = run_many(["ok:1"], config, scanner=good, send_notifications=False)
    assert outcomes[0].ok

    broken = FakeScanner(fail_with=ScannerError("registry unreachable"))
    outcomes = run_many(["a:1", "b:1"], config, scanner=broken, send_notifications=False)
    assert len(outcomes) == 2
    assert all(o.error for o in outcomes)
    assert all(not o.decision.passed for o in outcomes)


def test_notifications_never_break_a_run(config, monkeypatch):
    config.notifications.slack.enabled = True
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    outcome = run_scan("app:1", config, scanner=FakeScanner(), send_notifications=True)
    assert outcome.decision.passed
    assert outcome.notifications["slack"].startswith("error:") or \
           outcome.notifications["slack"].startswith("skipped:")


def test_outcome_serialises_to_json(config):
    outcome = run_scan("app:1", config, scanner=FakeScanner([make_vuln()]), send_notifications=False)
    payload = json.loads(json.dumps(outcome.to_dict()))
    assert payload["policy"]["verdict"] in {"PASS", "FAIL"}
    assert payload["image"] == "app:1"


def test_cli_exit_codes(config, tmp_path, monkeypatch, capsys):
    from aegis import cli

    config_path = tmp_path / "aegis.yml"
    config_path.write_text(
        f"storage: {{database: {tmp_path / 'cli.db'}}}\n"
        f"reporting: {{output_dir: {tmp_path / 'r'}}}\n"
        f"exceptions: {{file: {tmp_path / 'e.yml'}}}\n"
        "metrics: {enabled: false}\n"
        "policy: {fail_on: HIGH}\n"
    )
    monkeypatch.setattr(cli, "get_scanner", lambda cfg: FakeScanner([make_vuln(severity=Severity.CRITICAL)]))
    monkeypatch.setattr("aegis.pipeline.get_scanner", lambda cfg: FakeScanner([make_vuln(severity=Severity.CRITICAL)]))

    assert cli.main(["-c", str(config_path), "scan", "app:1", "--no-notify"]) == 1
    assert cli.main(["-c", str(config_path), "scan", "app:1", "--no-notify", "--exit-zero"]) == 0
    assert cli.main(["-c", str(config_path), "scan", "app:1", "--no-notify", "--warn-only"]) == 0
    assert cli.main(["-c", str(config_path), "images"]) == 0
    assert cli.main(["-c", str(config_path), "history"]) == 0


def test_cli_exceptions_add_and_list(tmp_path, capsys):
    from aegis import cli

    config_path = tmp_path / "aegis.yml"
    config_path.write_text(f"exceptions: {{file: {tmp_path / 'e.yml'}}}\n")

    assert cli.main([
        "-c", str(config_path), "exceptions", "add", "CVE-2030-1",
        "--reason", "no upstream fix yet", "--days", "30",
    ]) == 0
    assert cli.main(["-c", str(config_path), "exceptions", "list"]) == 0
    assert "CVE-2030-1" in capsys.readouterr().out
