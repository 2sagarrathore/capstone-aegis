from datetime import datetime, timedelta, timezone

from aegis.models import PolicyDecision, ScanResult, Severity

from .conftest import make_result, make_vuln


def record(store, image, vulns, when=None, verdict="PASS"):
    result = make_result(image=image, vulns=vulns)
    if when:
        result.scanned_at = when
    store.record(result, PolicyDecision(passed=verdict == "PASS"))
    return result


def test_record_and_read_back(store):
    result = record(store, "app:1", [make_vuln(severity=Severity.CRITICAL)])
    rows = store.scans()
    assert len(rows) == 1
    assert rows[0]["image"] == "app:1"
    assert rows[0]["critical"] == 1
    assert len(store.findings(result.scan_id)) == 1


def test_record_is_idempotent(store):
    result = make_result(vulns=[make_vuln()])
    decision = PolicyDecision(passed=False)
    store.record(result, decision)
    store.record(result, decision)
    assert len(store.scans()) == 1
    assert len(store.findings(result.scan_id)) == 1


def test_suppressed_findings_are_stored_but_excluded_by_default(store):
    result = make_result(vulns=[make_vuln("CVE-A")])
    result.suppressed = [make_vuln("CVE-B")]
    store.record(result, PolicyDecision(passed=True))
    assert len(store.findings(result.scan_id)) == 1
    assert len(store.findings(result.scan_id, include_suppressed=True)) == 2


def test_images_returns_only_the_latest_scan_per_image(store):
    older = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat(timespec="seconds")
    record(store, "app:1", [make_vuln("CVE-A"), make_vuln("CVE-B")], when=older)
    record(store, "app:1", [make_vuln("CVE-A")])
    record(store, "other:1", [])

    rows = {row["image"]: row for row in store.images()}
    assert len(rows) == 2
    assert rows["app:1"]["total"] == 1


def test_diff_detects_introduced_and_resolved(store):
    older = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(timespec="seconds")
    record(store, "app:1", [make_vuln("CVE-A"), make_vuln("CVE-B")], when=older)

    current = make_result(image="app:1", vulns=[make_vuln("CVE-B"), make_vuln("CVE-C")])
    diff = store.diff_with_previous(current)

    assert [v.vuln_id for v in diff.introduced] == ["CVE-C"]
    assert [v.vuln_id for v in diff.resolved] == ["CVE-A"]
    assert diff.unchanged_count == 1
    assert diff.has_changes


def test_first_scan_treats_everything_as_introduced(store):
    current = make_result(image="new:1", vulns=[make_vuln("CVE-A")])
    diff = store.diff_with_previous(current)
    assert len(diff.introduced) == 1
    assert diff.previous_scan_id is None


def test_diff_filters_by_severity(store):
    current = make_result(image="new:1", vulns=[
        make_vuln("CVE-crit", severity=Severity.CRITICAL),
        make_vuln("CVE-low", severity=Severity.LOW),
    ])
    diff = store.diff_with_previous(current)
    assert [v.vuln_id for v in diff.introduced_at_or_above(Severity.HIGH)] == ["CVE-crit"]


def test_summary_aggregates_latest_state(store):
    record(store, "a:1", [make_vuln(severity=Severity.CRITICAL)], verdict="FAIL")
    record(store, "b:1", [make_vuln(severity=Severity.LOW)])
    summary = store.summary()
    assert summary["images_tracked"] == 2
    assert summary["critical"] == 1
    assert summary["failing_images"] == 1


def test_trend_buckets_by_day(store):
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(timespec="seconds")
    record(store, "a:1", [make_vuln(severity=Severity.HIGH)], when=yesterday)
    record(store, "a:1", [make_vuln(severity=Severity.HIGH), make_vuln("CVE-2", severity=Severity.HIGH)])
    trend = store.trend(days=7)
    assert len(trend) == 2
    assert trend[-1]["high"] == 2


def test_trend_counts_each_image_once_per_day(store):
    """Three rebuilds of one image must not look like three times the backlog."""
    today = datetime.now(timezone.utc)
    for minutes, count in ((30, 5), (20, 5), (10, 3)):
        when = (today - timedelta(minutes=minutes)).isoformat(timespec="milliseconds")
        record(store, "a:1", [make_vuln(f"CVE-{i}", severity=Severity.HIGH) for i in range(count)], when=when)

    trend = store.trend(days=1)
    assert len(trend) == 1
    assert trend[0]["high"] == 3      # the last scan of the day, not 5+5+3
    assert trend[0]["scans"] == 1


def test_top_packages_ranks_by_finding_count(store):
    record(store, "a:1", [
        make_vuln("CVE-1", package="openssl", severity=Severity.CRITICAL),
        make_vuln("CVE-2", package="openssl", severity=Severity.HIGH),
        make_vuln("CVE-3", package="zlib", severity=Severity.LOW),
    ])
    packages = store.top_packages()
    assert packages[0]["package"] == "openssl"
    assert packages[0]["findings"] == 2
    assert packages[0]["critical"] == 1


def test_stale_images(store):
    old = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat(timespec="seconds")
    record(store, "stale:1", [], when=old)
    record(store, "fresh:1", [])
    assert [row["image"] for row in store.stale_images(hours=24)] == ["stale:1"]


def test_purge_removes_old_scans_and_their_findings(store):
    old = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat(timespec="seconds")
    stale = record(store, "a:1", [make_vuln()], when=old)
    record(store, "a:1", [make_vuln()])

    assert store.purge_older_than(365) == 1
    assert len(store.scans()) == 1
    assert store.findings(stale.scan_id) == []


def test_scan_filters(store):
    record(store, "team/api:1", [])
    record(store, "team/web:1", [])
    assert len(store.scans(image="team/api*")) == 1
    assert len(store.scans(limit=1)) == 1


def test_waived_findings_are_not_counted_as_resolved(store):
    """A signed waiver is not a patch, and must not read like one."""
    older = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(timespec="seconds")
    record(store, "app:1", [make_vuln("CVE-A"), make_vuln("CVE-B"), make_vuln("CVE-C")], when=older)

    current = make_result(image="app:1", vulns=[make_vuln("CVE-A")])
    current.suppressed = [make_vuln("CVE-B")]        # waived by an exception
    diff = store.diff_with_previous(current)         # CVE-C was genuinely patched

    assert [v.vuln_id for v in diff.waived] == ["CVE-B"]
    assert [v.vuln_id for v in diff.resolved] == ["CVE-C"]
    assert diff.has_changes
