import json

from aegis.config import AegisConfig
from aegis.models import PolicyDecision, Severity
from aegis.reporting import generate, human_size, safe_slug
from aegis.reporting.html_report import render_html
from aegis.reporting.markdown_report import render_markdown
from aegis.storage import ScanDiff

from .conftest import make_result, make_vuln


def sample():
    result = make_result(image="registry.io/team/app:1.2.3", vulns=[
        make_vuln("CVE-2024-1", package="openssl", severity=Severity.CRITICAL),
        make_vuln("CVE-2024-2", package="zlib", severity=Severity.LOW, fixed_version=""),
    ])
    result.suppressed = [make_vuln("CVE-2024-3", package="curl")]
    return result, PolicyDecision(passed=False, reasons=["1 CRITICAL finding(s)"])


def test_safe_slug_is_filename_safe():
    assert safe_slug("registry.io/team/app:1.2.3") == "registry.io_team_app_1.2.3"
    assert "/" not in safe_slug("a/b:c")


def test_human_size():
    assert human_size(0) == "unknown"
    assert human_size(512) == "512 B"
    assert human_size(151721472).endswith("MB")


def test_generate_writes_every_configured_format(tmp_path):
    result, decision = sample()
    config = AegisConfig()
    config.reporting.formats = ["json", "html", "markdown"]
    written = generate(result, decision, config, output_dir=tmp_path)

    assert set(written) == {"json", "html", "markdown"}
    for path in written.values():
        assert path.exists() and path.stat().st_size > 0
    # A stable "latest" pointer means CI links never go stale.
    assert (tmp_path / "latest_registry.io_team_app_1.2.3.html").exists()


def test_json_report_carries_policy_and_summary(tmp_path):
    result, decision = sample()
    config = AegisConfig()
    config.reporting.formats = ["json"]
    path = generate(result, decision, config, output_dir=tmp_path)["json"]
    payload = json.loads(path.read_text())

    assert payload["policy"]["verdict"] == "FAIL"
    assert payload["summary"]["CRITICAL"] == 1
    assert payload["summary"]["suppressed"] == 1
    assert payload["vulnerabilities"][0]["vuln_id"] == "CVE-2024-1"


def test_html_report_is_self_contained():
    result, decision = sample()
    html = render_html(result, decision, AegisConfig())
    assert "<html" in html and "</html>" in html
    assert "CVE-2024-1" in html
    # No external assets: the report must open from a file:// URL offline.
    assert "http://" not in html.replace("http://www.w3.org", "")
    assert "cdn." not in html


def test_html_escapes_untrusted_scanner_text():
    result, decision = sample()
    result.vulnerabilities[0].__dict__["title"] = "<script>alert(1)</script>"
    html = render_html(result, decision, AegisConfig())
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_markdown_includes_diff_when_present():
    result, decision = sample()
    diff = ScanDiff(introduced=[make_vuln("CVE-NEW", severity=Severity.CRITICAL)],
                    resolved=[], unchanged_count=3, previous_scan_id="abc")
    text = render_markdown(result, decision, AegisConfig(), diff)
    assert "Change since previous scan" in text
    assert "CVE-NEW" in text
    assert "| Critical | High |" in text


def test_report_truncates_very_large_tables():
    result, decision = sample()
    result.vulnerabilities = [
        make_vuln(f"CVE-{i}", package=f"pkg{i}") for i in range(600)
    ]
    config = AegisConfig()
    config.reporting.max_rows_in_html = 50
    html = render_html(result, decision, config)
    assert "of 600 shown" in html
