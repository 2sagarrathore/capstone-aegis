import json

import pytest

from aegis.config import AegisConfig
from aegis.dashboard import create_app
from aegis.models import PolicyDecision, ScanResult, Severity
from aegis.storage import ScanStore

from .conftest import make_result, make_vuln


@pytest.fixture
def client(tmp_path):
    config = AegisConfig()
    config.storage.database = str(tmp_path / "aegis.db")
    config.exceptions.file = str(tmp_path / "exceptions.yml")

    store = ScanStore(config.storage.database)
    result = make_result(image="team/api:1.0", vulns=[
        make_vuln("CVE-2024-1", package="openssl", severity=Severity.CRITICAL),
        make_vuln("CVE-2024-2", package="zlib", severity=Severity.MEDIUM),
    ])
    store.record(result, PolicyDecision(passed=False, reasons=["1 CRITICAL finding(s)"]), source="test")

    app = create_app(config)
    app.config["TESTING"] = True
    return app.test_client()


def test_overview_lists_tracked_images(client):
    page = client.get("/")
    assert page.status_code == 200
    assert b"team/api:1.0" in page.data
    assert b"FAIL" in page.data


def test_image_page_shows_findings(client):
    page = client.get("/image/team/api:1.0")
    assert page.status_code == 200
    assert b"CVE-2024-1" in page.data
    assert b"1 CRITICAL finding(s)" in page.data


def test_unknown_image_renders_without_error(client):
    page = client.get("/image/never/scanned:1")
    assert page.status_code == 200
    assert b"No scans recorded" in page.data


def test_scan_history_filters(client):
    assert b"team/api:1.0" in client.get("/scans?days=30").data
    assert b"team/api:1.0" not in client.get("/scans?verdict=PASS").data


def test_json_api(client):
    summary = json.loads(client.get("/api/summary").data)
    assert summary["images_tracked"] == 1
    assert summary["critical"] == 1

    images = json.loads(client.get("/api/images").data)
    scan_id = images[0]["scan_id"]
    findings = json.loads(client.get(f"/api/findings/{scan_id}").data)
    assert {f["vuln_id"] for f in findings} == {"CVE-2024-1", "CVE-2024-2"}

    critical = json.loads(client.get(f"/api/findings/{scan_id}?severity=CRITICAL").data)
    assert len(critical) == 1


def test_metrics_endpoint_is_prometheus_formatted(client):
    response = client.get("/metrics")
    assert response.status_code == 200
    body = response.data.decode()
    assert "# TYPE aegis_vulnerabilities gauge" in body
    assert 'aegis_vulnerabilities{image="team/api:1.0",severity="CRITICAL"} 1.0' in body
    assert 'aegis_policy_pass{image="team/api:1.0"} 0.0' in body


def test_healthz(client):
    assert json.loads(client.get("/healthz").data)["status"] == "ok"


def test_empty_database_renders(tmp_path):
    config = AegisConfig()
    config.storage.database = str(tmp_path / "empty.db")
    config.exceptions.file = str(tmp_path / "exceptions.yml")
    client = create_app(config).test_client()
    page = client.get("/")
    assert page.status_code == 200
    assert b"No scans recorded yet" in page.data
