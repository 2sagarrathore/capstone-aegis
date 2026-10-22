from datetime import date, timedelta

import pytest
import yaml

from aegis.exceptions_store import ExceptionError, ExceptionStore, VulnerabilityException
from aegis.models import Severity

from .conftest import make_result, make_vuln


def entry(**kwargs):
    base = {
        "vuln_id": "CVE-2024-0001",
        "reason": "not reachable in this deployment",
        "expires": date.today() + timedelta(days=30),
    }
    base.update(kwargs)
    return VulnerabilityException(**base)


def test_exception_without_expiry_is_rejected():
    with pytest.raises(ExceptionError, match="expires"):
        VulnerabilityException.from_dict({"id": "CVE-1", "reason": "because"})


def test_exception_without_reason_is_rejected():
    with pytest.raises(ExceptionError, match="reason"):
        VulnerabilityException.from_dict({"id": "CVE-1", "expires": "2099-01-01"})


def test_expired_exception_does_not_match():
    expired = entry(expires=date.today() - timedelta(days=1))
    assert expired.is_expired()
    assert not expired.matches(make_vuln(), "app:1")


def test_package_and_image_globs():
    scoped = entry(package="openssl*", image="internal/*")
    assert scoped.matches(make_vuln(package="openssl"), "internal/api:1")
    assert not scoped.matches(make_vuln(package="curl"), "internal/api:1")
    assert not scoped.matches(make_vuln(package="openssl"), "public/api:1")


def test_apply_moves_matches_to_suppressed():
    store = ExceptionStore([entry(vuln_id="CVE-2024-0001")])
    result = make_result(vulns=[
        make_vuln("CVE-2024-0001", severity=Severity.CRITICAL),
        make_vuln("CVE-2024-0002", severity=Severity.HIGH),
    ])
    store.apply(result)
    assert [v.vuln_id for v in result.vulnerabilities] == ["CVE-2024-0002"]
    assert [v.vuln_id for v in result.suppressed] == ["CVE-2024-0001"]
    assert result.counts()["CRITICAL"] == 0


def test_wildcard_id_matches_any_cve_for_that_package():
    store = ExceptionStore([entry(vuln_id="*", package="busybox")])
    result = make_result(vulns=[
        make_vuln("CVE-A", package="busybox"),
        make_vuln("CVE-B", package="openssl"),
    ])
    store.apply(result)
    assert [v.vuln_id for v in result.vulnerabilities] == ["CVE-B"]


def test_add_defaults_to_the_configured_window():
    store = ExceptionStore()
    added = store.add("CVE-2030-1", "waiting for upstream", default_expiry_days=45)
    assert added.days_remaining() == 45
    assert len(store) == 1


def test_add_replaces_an_identical_scope():
    store = ExceptionStore()
    store.add("CVE-1", "first")
    store.add("CVE-1", "second")
    assert len(store) == 1
    assert store.entries[0].reason == "second"


def test_prune_and_expiring_window():
    store = ExceptionStore([
        entry(vuln_id="CVE-old", expires=date.today() - timedelta(days=2)),
        entry(vuln_id="CVE-soon", expires=date.today() + timedelta(days=3)),
        entry(vuln_id="CVE-later", expires=date.today() + timedelta(days=200)),
    ])
    assert [e.vuln_id for e in store.expiring_within(14)] == ["CVE-soon"]
    removed = store.prune_expired()
    assert [e.vuln_id for e in removed] == ["CVE-old"]
    assert len(store) == 2


def test_round_trip_through_yaml(tmp_path):
    path = tmp_path / "exceptions.yml"
    store = ExceptionStore()
    store.add("CVE-2030-9", "approved by security", package="zlib", image="app:*", approved_by="sec@acme")
    store.save(path)

    saved = yaml.safe_load(path.read_text())
    assert saved["version"] == 1

    reloaded = ExceptionStore.load(path)
    assert len(reloaded) == 1
    assert reloaded.entries[0].approved_by == "sec@acme"


def test_missing_file_loads_empty(tmp_path):
    assert len(ExceptionStore.load(tmp_path / "nope.yml")) == 0
