import yaml

from aegis.config import AegisConfig, find_config_file, load_config
from aegis.models import Severity


def write(tmp_path, data):
    path = tmp_path / "aegis.yml"
    path.write_text(yaml.safe_dump(data))
    return path


def test_defaults_are_sane():
    config = AegisConfig()
    assert config.scanner.engine == "trivy"
    assert config.fail_on_severity is Severity.HIGH
    assert config.scanner.retries >= 1


def test_nested_yaml_is_parsed(tmp_path):
    path = write(tmp_path, {
        "scanner": {"retries": 5, "severities": ["HIGH"]},
        "policy": {"fail_on": "CRITICAL", "max_allowed": {"CRITICAL": 2}},
        "notifications": {"slack": {"enabled": True, "min_severity": "MEDIUM"}},
    })
    config = load_config(str(path))
    assert config.scanner.retries == 5
    assert config.policy.max_allowed == {"CRITICAL": 2}
    assert config.notifications.slack.enabled is True
    assert config.notifications.slack.min_severity == "MEDIUM"


def test_unknown_keys_are_ignored(tmp_path):
    path = write(tmp_path, {"scanner": {"retries": 1, "from_a_future_version": True}})
    assert load_config(str(path)).scanner.retries == 1


def test_env_overrides_the_file(tmp_path, monkeypatch):
    path = write(tmp_path, {"policy": {"fail_on": "LOW"}})
    monkeypatch.setenv("AEGIS_FAIL_ON", "critical")
    monkeypatch.setenv("AEGIS_MAX_HIGH", "7")
    monkeypatch.setenv("AEGIS_IGNORE_UNFIXED", "true")
    config = load_config(str(path))
    assert config.policy.fail_on == "CRITICAL"
    assert config.policy.max_allowed["HIGH"] == 7
    assert config.scanner.ignore_unfixed is True


def test_bad_env_integer_is_ignored(tmp_path, monkeypatch):
    path = write(tmp_path, {})
    monkeypatch.setenv("AEGIS_MAX_HIGH", "not-a-number")
    assert "HIGH" not in load_config(str(path)).policy.max_allowed


def test_relative_paths_resolve_against_the_config_file(tmp_path):
    path = write(tmp_path, {"storage": {"database": "data/aegis.db"}})
    config = load_config(str(path))
    assert config.resolve(config.storage.database) == (tmp_path / "data" / "aegis.db").resolve()


def test_absolute_paths_are_left_alone(tmp_path):
    path = write(tmp_path, {"storage": {"database": "/var/lib/aegis.db"}})
    config = load_config(str(path))
    assert str(config.resolve(config.storage.database)) == "/var/lib/aegis.db"


def test_config_is_discovered_from_a_parent_directory(tmp_path):
    write(tmp_path, {"policy": {"fail_on": "LOW"}})
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    assert find_config_file(start=nested).parent == tmp_path


def test_missing_explicit_config_raises(tmp_path):
    try:
        load_config(str(tmp_path / "nope.yml"))
    except FileNotFoundError as exc:
        assert "not found" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected FileNotFoundError")


def test_fixable_only_env_override(tmp_path, monkeypatch):
    path = write(tmp_path, {"policy": {"fail_on_fixable_only": False}})
    monkeypatch.setenv("AEGIS_FIXABLE_ONLY", "true")
    assert load_config(str(path)).policy.fail_on_fixable_only is True
