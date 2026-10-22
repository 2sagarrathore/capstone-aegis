from aegis.models import ScanResult, Severity, Vulnerability

from .conftest import make_result, make_vuln


def test_severity_ordering_is_by_urgency():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.UNKNOWN
    assert Severity.HIGH >= Severity.HIGH


def test_severity_parse_tolerates_junk():
    assert Severity.parse("critical") is Severity.CRITICAL
    assert Severity.parse(" High ") is Severity.HIGH
    assert Severity.parse("bogus") is Severity.UNKNOWN
    assert Severity.parse(None) is Severity.UNKNOWN


def test_fixable_follows_fixed_version():
    assert make_vuln(fixed_version="1.2.3").fixable
    assert not make_vuln(fixed_version="").fixable


def test_counts_and_helpers():
    result = make_result(vulns=[
        make_vuln("CVE-1", severity=Severity.CRITICAL),
        make_vuln("CVE-2", severity=Severity.HIGH),
        make_vuln("CVE-3", severity=Severity.LOW, fixed_version=""),
    ])
    assert result.counts()["CRITICAL"] == 1
    assert result.count_at_or_above(Severity.HIGH) == 2
    assert result.fixable_count() == 2
    assert result.total == 3


def test_sort_puts_critical_and_fixable_first():
    result = make_result(vulns=[
        make_vuln("CVE-low", severity=Severity.LOW),
        make_vuln("CVE-crit-nofix", severity=Severity.CRITICAL, fixed_version=""),
        make_vuln("CVE-crit-fix", severity=Severity.CRITICAL),
    ])
    order = [v.vuln_id for v in result.sorted_vulnerabilities()]
    assert order == ["CVE-crit-fix", "CVE-crit-nofix", "CVE-low"]


def test_scan_id_is_stable_and_distinct():
    one = make_result()
    same = ScanResult(image=one.image, scanned_at=one.scanned_at)
    assert one.scan_id == same.scan_id
    assert one.scan_id != ScanResult(image="other:1", scanned_at=one.scanned_at).scan_id


def test_round_trip_through_dict():
    result = make_result(vulns=[make_vuln(severity=Severity.CRITICAL)])
    restored = ScanResult.from_dict(result.to_dict())
    assert restored.image == result.image
    assert restored.counts() == result.counts()
    assert restored.vulnerabilities[0].severity is Severity.CRITICAL


def test_fingerprint_identifies_a_finding():
    assert make_vuln().fingerprint == "CVE-2024-0001:openssl:1.1.1k"
