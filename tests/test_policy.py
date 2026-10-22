from aegis.config import AegisConfig
from aegis.models import Severity
from aegis.policy import describe, evaluate

from .conftest import make_result, make_vuln


def result_with(**counts):
    vulns = []
    for severity, number in counts.items():
        for index in range(number):
            vulns.append(
                make_vuln(f"CVE-{severity}-{index}", package=f"pkg{index}",
                          severity=Severity.parse(severity))
            )
    return make_result(vulns=vulns)


def test_clean_image_passes():
    assert evaluate(make_result(), AegisConfig()).passed


def test_floor_fails_on_high_and_above():
    config = AegisConfig()
    config.policy.fail_on = "HIGH"
    assert not evaluate(result_with(HIGH=1), config).passed
    assert not evaluate(result_with(CRITICAL=1), config).passed
    assert evaluate(result_with(MEDIUM=50, LOW=90), config).passed


def test_budget_overrides_the_floor_for_that_severity():
    config = AegisConfig()
    config.policy.fail_on = "HIGH"
    config.policy.max_allowed = {"HIGH": 5, "CRITICAL": 0}
    assert evaluate(result_with(HIGH=5), config).passed
    decision = evaluate(result_with(HIGH=6), config)
    assert not decision.passed
    assert "exceed the budget of 5" in decision.reasons[0]
    assert decision.breached_severities == ["HIGH"]


def test_critical_budget_of_zero_still_fails():
    config = AegisConfig()
    config.policy.max_allowed = {"CRITICAL": 0, "HIGH": 100}
    assert not evaluate(result_with(CRITICAL=1, HIGH=99), config).passed


def test_fixable_only_ignores_unfixable_findings():
    config = AegisConfig()
    config.policy.fail_on = "HIGH"
    config.policy.fail_on_fixable_only = True
    unfixable = make_result(vulns=[make_vuln(severity=Severity.CRITICAL, fixed_version="")])
    assert evaluate(unfixable, config).passed

    fixable = make_result(vulns=[make_vuln(severity=Severity.CRITICAL, fixed_version="3.0")])
    assert not evaluate(fixable, config).passed


def test_max_total_is_independent_of_severity():
    config = AegisConfig()
    config.policy.fail_on = "CRITICAL"
    config.policy.max_total = 10
    decision = evaluate(result_with(LOW=11), config)
    assert not decision.passed
    assert "max_total" in decision.reasons[0]


def test_warn_only_reports_but_passes():
    config = AegisConfig()
    config.policy.warn_only = True
    decision = evaluate(result_with(CRITICAL=5), config)
    assert decision.passed
    assert decision.exit_code == 0
    assert any("warn_only" in reason for reason in decision.reasons)


def test_scan_errors_fail_the_gate():
    config = AegisConfig()
    result = make_result()
    result.errors.append("registry unreachable")
    assert not evaluate(result, config).passed


def test_describe_is_readable():
    config = AegisConfig()
    config.policy.max_allowed = {"CRITICAL": 0}
    config.policy.warn_only = True
    text = describe(config)
    assert "fail_on>=HIGH" in text and "CRITICAL<=0" in text and "WARN-ONLY" in text
