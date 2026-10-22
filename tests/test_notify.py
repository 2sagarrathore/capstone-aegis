from types import SimpleNamespace

from aegis.config import SlackConfig, TeamsConfig
from aegis.models import PolicyDecision, Severity
from aegis.notify import should_notify
from aegis.notify.slack import SlackNotifier
from aegis.notify.teams import TeamsNotifier
from aegis.storage import ScanDiff

from .conftest import make_result, make_vuln


def test_failed_gate_always_notifies():
    wanted, reason = should_notify(make_result(), PolicyDecision(passed=False), None, "HIGH", False)
    assert wanted and "failed" in reason


def test_pass_is_quiet_by_default():
    wanted, _ = should_notify(make_result(), PolicyDecision(passed=True), None, "HIGH", False)
    assert not wanted


def test_pass_notifies_when_configured():
    wanted, _ = should_notify(make_result(), PolicyDecision(passed=True), None, "HIGH", True)
    assert wanted


def test_new_high_severity_finding_notifies_even_on_pass():
    diff = ScanDiff(introduced=[make_vuln(severity=Severity.CRITICAL)], resolved=[], unchanged_count=0)
    wanted, reason = should_notify(make_result(), PolicyDecision(passed=True), diff, "HIGH", False)
    assert wanted and "new finding" in reason


def test_new_low_severity_finding_stays_quiet():
    diff = ScanDiff(introduced=[make_vuln(severity=Severity.LOW)], resolved=[], unchanged_count=0)
    wanted, _ = should_notify(make_result(), PolicyDecision(passed=True), diff, "HIGH", False)
    assert not wanted


def test_slack_payload_shape():
    result = make_result(vulns=[make_vuln(severity=Severity.CRITICAL)])
    payload = SlackNotifier(SlackConfig(dashboard_url="https://aegis.internal")).build_payload(
        result, PolicyDecision(passed=False, reasons=["1 CRITICAL finding(s)"])
    )
    assert payload["blocks"][0]["type"] == "header"
    assert "FAILED" in payload["text"]
    assert any(block.get("type") == "actions" for block in payload["blocks"])


def test_slack_requires_the_webhook_env(monkeypatch):
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    notifier = SlackNotifier(SlackConfig(enabled=True))
    try:
        notifier.webhook_url()
    except Exception as exc:
        assert "SLACK_WEBHOOK_URL" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected a NotifierError")


def test_teams_card_colour_tracks_the_verdict():
    result = make_result()
    passing = TeamsNotifier(TeamsConfig()).build_payload(result, PolicyDecision(passed=True))
    failing = TeamsNotifier(TeamsConfig()).build_payload(result, PolicyDecision(passed=False))
    assert passing["themeColor"] != failing["themeColor"]
    assert failing["title"].startswith("Vulnerability gate FAILED")


class FakeResponse:
    def __init__(self, status_code=200, text="ok"):
        self.status_code = status_code
        self.text = text


def test_slack_send_posts_the_payload(monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.test/abc")
    posted = {}

    def fake_post(url, json=None, timeout=None):
        posted["url"] = url
        posted["json"] = json
        return FakeResponse()

    monkeypatch.setattr("aegis.notify.slack.requests.post", fake_post)
    SlackNotifier(SlackConfig(enabled=True)).send(make_result(), PolicyDecision(passed=False))
    assert posted["url"].startswith("https://hooks.slack.test/")
    assert "blocks" in posted["json"]


def test_slack_retries_server_errors_then_gives_up(monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.test/abc")
    monkeypatch.setattr("aegis.notify.slack.time.sleep", lambda seconds: None)
    attempts = {"n": 0}

    def fake_post(url, json=None, timeout=None):
        attempts["n"] += 1
        return FakeResponse(status_code=503, text="unavailable")

    monkeypatch.setattr("aegis.notify.slack.requests.post", fake_post)
    try:
        SlackNotifier(SlackConfig(enabled=True)).send(make_result(), PolicyDecision(passed=False))
    except Exception as exc:
        assert "after 3 attempts" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected a NotifierError")
    assert attempts["n"] == 3


def test_slack_does_not_retry_a_bad_request(monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.test/abc")
    attempts = {"n": 0}

    def fake_post(url, json=None, timeout=None):
        attempts["n"] += 1
        return FakeResponse(status_code=400, text="invalid_payload")

    monkeypatch.setattr("aegis.notify.slack.requests.post", fake_post)
    with __import__("pytest").raises(Exception):
        SlackNotifier(SlackConfig(enabled=True)).send(make_result(), PolicyDecision(passed=False))
    assert attempts["n"] == 1


def test_dispatch_reports_per_channel_status(monkeypatch):
    from aegis.config import AegisConfig
    from aegis.notify import dispatch

    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.test/abc")
    monkeypatch.setattr("aegis.notify.slack.requests.post", lambda *a, **k: FakeResponse())

    config = AegisConfig()
    config.notifications.slack.enabled = True
    outcomes = dispatch(make_result(), PolicyDecision(passed=False), config)
    assert outcomes["slack"] == "sent"
    assert "teams" not in outcomes  # disabled channels are not contacted
