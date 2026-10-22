"""Configuration loading: YAML file -> dataclasses -> environment overrides.

Precedence (highest wins): CLI flag > environment variable > YAML file > default.
CI systems only reliably hand you environment variables, so every knob that a
pipeline might want to change has an ``AEGIS_*`` override.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Any, get_type_hints

import yaml

from .models import Severity

DEFAULT_CONFIG_NAMES = ("aegis.yml", "aegis.yaml", ".aegis.yml")


def _env_bool(name: str) -> bool | None:
    raw = os.environ.get(name)
    if raw is None:
        return None
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str) -> int | None:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return None
    try:
        return int(raw)
    except ValueError:
        return None


@dataclass
class ScannerConfig:
    engine: str = "trivy"
    timeout_seconds: int = 600
    retries: int = 2
    retry_backoff_seconds: float = 5.0
    ignore_unfixed: bool = False
    severities: list[str] = field(
        default_factory=lambda: ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    )
    cache_dir: str = ""
    offline: bool = False
    skip_db_update: bool = False
    db_repository: str = ""
    scanners: list[str] = field(default_factory=lambda: ["vuln"])
    platform: str = ""


@dataclass
class PolicyConfig:
    """Build-gate rules.

    ``fail_on`` is the severity floor that breaks a build.  ``max_allowed``
    overrides it per severity so a team can tolerate, say, 10 HIGHs while
    holding CRITICALs at zero.
    """

    fail_on: str = "HIGH"
    max_allowed: dict[str, int] = field(default_factory=dict)
    fail_on_fixable_only: bool = False
    max_total: int | None = None
    warn_only: bool = False


@dataclass
class ExceptionsConfig:
    file: str = "exceptions.yml"
    default_expiry_days: int = 90
    warn_on_expiring_within_days: int = 14


@dataclass
class ReportingConfig:
    output_dir: str = "reports"
    formats: list[str] = field(default_factory=lambda: ["json", "html", "markdown"])
    max_rows_in_html: int = 500
    include_suppressed: bool = True


@dataclass
class SlackConfig:
    enabled: bool = False
    webhook_url_env: str = "SLACK_WEBHOOK_URL"
    min_severity: str = "HIGH"
    notify_on_pass: bool = False
    dashboard_url: str = ""
    timeout_seconds: int = 10


@dataclass
class TeamsConfig:
    enabled: bool = False
    webhook_url_env: str = "TEAMS_WEBHOOK_URL"
    min_severity: str = "HIGH"
    notify_on_pass: bool = False
    dashboard_url: str = ""
    timeout_seconds: int = 10


@dataclass
class NotificationsConfig:
    slack: SlackConfig = field(default_factory=SlackConfig)
    teams: TeamsConfig = field(default_factory=TeamsConfig)


@dataclass
class StorageConfig:
    database: str = "aegis.db"
    retention_days: int = 365


@dataclass
class MetricsConfig:
    enabled: bool = True
    textfile_path: str = "reports/aegis_metrics.prom"
    pushgateway_url: str = ""
    job_name: str = "aegis_scanner"


@dataclass
class RescanConfig:
    stale_after_hours: int = 24
    images: list[str] = field(default_factory=list)


@dataclass
class AegisConfig:
    scanner: ScannerConfig = field(default_factory=ScannerConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    exceptions: ExceptionsConfig = field(default_factory=ExceptionsConfig)
    reporting: ReportingConfig = field(default_factory=ReportingConfig)
    notifications: NotificationsConfig = field(default_factory=NotificationsConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    metrics: MetricsConfig = field(default_factory=MetricsConfig)
    rescan: RescanConfig = field(default_factory=RescanConfig)
    source_path: str = ""

    @property
    def fail_on_severity(self) -> Severity:
        return Severity.parse(self.policy.fail_on)

    def resolve(self, value: str) -> Path:
        """Make a configured path absolute.

        Relative paths resolve against the **config file's** directory, so a
        pipeline can cd anywhere and still write to the same database. With no
        config file, they resolve against the working directory.
        """
        path = Path(value).expanduser()
        if path.is_absolute():
            return path
        if self.source_path:
            return (Path(self.source_path).parent / path).resolve()
        return (Path.cwd() / path).resolve()


def _build(cls: type, data: Any) -> Any:
    """Recursively instantiate nested dataclasses from plain dicts."""
    if not is_dataclass(cls) or not isinstance(data, dict):
        return data
    hints = get_type_hints(cls)
    known = {f.name for f in fields(cls)}
    kwargs: dict[str, Any] = {}
    for key, value in data.items():
        if key not in known:
            continue  # unknown keys are ignored so old configs keep working
        field_type = hints.get(key)
        if is_dataclass(field_type) and isinstance(value, dict):
            kwargs[key] = _build(field_type, value)
        else:
            kwargs[key] = value
    return cls(**kwargs)


def find_config_file(explicit: str | None = None, start: Path | None = None) -> Path | None:
    if explicit:
        path = Path(explicit).expanduser()
        if not path.exists():
            raise FileNotFoundError(f"config file not found: {path}")
        return path
    env_path = os.environ.get("AEGIS_CONFIG")
    if env_path:
        path = Path(env_path).expanduser()
        if path.exists():
            return path
    here = (start or Path.cwd()).resolve()
    for directory in [here, *here.parents]:
        for name in DEFAULT_CONFIG_NAMES:
            candidate = directory / name
            if candidate.exists():
                return candidate
    return None


def load_config(explicit: str | None = None) -> AegisConfig:
    path = find_config_file(explicit)
    data: dict[str, Any] = {}
    if path:
        with open(path, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
    config: AegisConfig = _build(AegisConfig, data)
    if path:
        config.source_path = str(path)
    _apply_env_overrides(config)
    return config


def _apply_env_overrides(config: AegisConfig) -> None:
    """Environment variables win over the YAML file -- this is how CI tunes runs."""
    if value := os.environ.get("AEGIS_FAIL_ON"):
        config.policy.fail_on = value.upper()
    if (value := _env_bool("AEGIS_WARN_ONLY")) is not None:
        config.policy.warn_only = value
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
        value_int = _env_int(f"AEGIS_MAX_{severity}")
        if value_int is not None:
            config.policy.max_allowed[severity] = value_int
    if (value := _env_bool("AEGIS_IGNORE_UNFIXED")) is not None:
        config.scanner.ignore_unfixed = value
    if (value := _env_bool("AEGIS_OFFLINE")) is not None:
        config.scanner.offline = value
    if (value := _env_bool("AEGIS_SKIP_DB_UPDATE")) is not None:
        config.scanner.skip_db_update = value
    if value := os.environ.get("AEGIS_CACHE_DIR"):
        config.scanner.cache_dir = value
    if (value_int := _env_int("AEGIS_TIMEOUT_SECONDS")) is not None:
        config.scanner.timeout_seconds = value_int
    if (value_int := _env_int("AEGIS_RETRIES")) is not None:
        config.scanner.retries = value_int
    if value := os.environ.get("AEGIS_OUTPUT_DIR"):
        config.reporting.output_dir = value
    if value := os.environ.get("AEGIS_FORMATS"):
        config.reporting.formats = [f.strip() for f in value.split(",") if f.strip()]
    if value := os.environ.get("AEGIS_DB"):
        config.storage.database = value
    if value := os.environ.get("AEGIS_EXCEPTIONS_FILE"):
        config.exceptions.file = value
    if (value := _env_bool("AEGIS_SLACK_ENABLED")) is not None:
        config.notifications.slack.enabled = value
    if (value := _env_bool("AEGIS_TEAMS_ENABLED")) is not None:
        config.notifications.teams.enabled = value
    if value := os.environ.get("AEGIS_DASHBOARD_URL"):
        config.notifications.slack.dashboard_url = value
        config.notifications.teams.dashboard_url = value
