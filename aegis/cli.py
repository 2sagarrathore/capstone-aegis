"""Aegis command line interface.

Exit codes are the contract CI depends on:

====  ==========================================================
  0   scan completed and the policy gate passed
  1   scan completed and the policy gate failed
  2   the scan could not be completed (bad image, scanner error)
  3   usage / configuration error
====  ==========================================================
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from . import __version__
from .config import AegisConfig, load_config
from .exceptions_store import ExceptionError, ExceptionStore
from .models import Severity
from .pipeline import run_many
from .policy import describe
from .reporting import human_size
from .scanner import ScannerError, ScannerNotInstalled, get_scanner
from .storage import ScanStore

EXIT_OK = 0
EXIT_POLICY_FAIL = 1
EXIT_SCAN_ERROR = 2
EXIT_USAGE = 3

ICONS = {"CRITICAL": "\033[31m●\033[0m", "HIGH": "\033[33m●\033[0m",
         "MEDIUM": "\033[93m●\033[0m", "LOW": "\033[34m●\033[0m", "UNKNOWN": "\033[90m●\033[0m"}

log = logging.getLogger("aegis")


def _supports_color() -> bool:
    return sys.stdout.isatty()


def c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _supports_color() else text


def setup_logging(verbosity: int, quiet: bool) -> None:
    level = logging.WARNING
    if quiet:
        level = logging.ERROR
    elif verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(level=level, format="%(levelname)-7s %(name)s: %(message)s")


# ---------------------------------------------------------------- scan ------


def _apply_cli_overrides(config: AegisConfig, args: argparse.Namespace) -> None:
    if getattr(args, "fail_on", None):
        config.policy.fail_on = args.fail_on.upper()
    for severity in ("critical", "high", "medium", "low"):
        value = getattr(args, f"max_{severity}", None)
        if value is not None:
            config.policy.max_allowed[severity.upper()] = value
    if getattr(args, "max_total", None) is not None:
        config.policy.max_total = args.max_total
    if getattr(args, "warn_only", False):
        config.policy.warn_only = True
    if getattr(args, "fixable_only", False):
        config.policy.fail_on_fixable_only = True
    if getattr(args, "ignore_unfixed", False):
        config.scanner.ignore_unfixed = True
    if getattr(args, "offline", False):
        config.scanner.offline = True
    if getattr(args, "severity", None):
        config.scanner.severities = [s.strip().upper() for s in args.severity.split(",")]
    if getattr(args, "output_dir", None):
        config.reporting.output_dir = args.output_dir
    if getattr(args, "format", None):
        config.reporting.formats = [f.strip().lower() for f in args.format.split(",")]
    if getattr(args, "exceptions_file", None):
        config.exceptions.file = args.exceptions_file
    if getattr(args, "db", None):
        config.storage.database = args.db


def print_summary(outcome, config: AegisConfig, quiet: bool = False) -> None:
    result, decision = outcome.result, outcome.decision
    counts = result.counts()
    verdict = c(f" {decision.verdict} ", "42;30" if decision.passed else "41;37")
    print(f"\n{verdict} {c(result.image, '1')}")
    if outcome.error:
        print(f"  {c('error:', '31')} {outcome.error}")
        return

    print(
        "  "
        + "  ".join(
            f"{ICONS[name] if _supports_color() else ''}{name.title()} {counts[name]}"
            for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        )
        + f"   fixable {result.fixable_count()}"
        + (f"   suppressed {len(result.suppressed)}" if result.suppressed else "")
    )
    if outcome.diff is not None and outcome.diff.previous_scan_id:
        waived = f", {len(outcome.diff.waived)} newly waived" if outcome.diff.waived else ""
        print(
            f"  change: +{len(outcome.diff.introduced)} introduced, "
            f"-{len(outcome.diff.resolved)} resolved{waived} vs previous scan"
        )
    if quiet:
        return

    for reason in decision.reasons:
        print(f"  {c('·', '90')} {reason}")

    top = [v for v in result.sorted_vulnerabilities() if v.severity >= Severity.HIGH][:5]
    if top:
        print(f"  {c('top findings:', '90')}")
        for vuln in top:
            fix = f"→ {vuln.fixed_version}" if vuln.fixed_version else "(no fix)"
            print(
                f"    {ICONS[vuln.severity.value] if _supports_color() else vuln.severity.value[:4]}"
                f" {vuln.vuln_id:<20} {vuln.package:<24} {vuln.installed_version:<22} {fix}"
            )
    for fmt, path in outcome.reports.items():
        print(f"  {c('report:', '90')} {fmt:<9} {path}")
    for channel, status in outcome.notifications.items():
        print(f"  {c('notify:', '90')} {channel:<9} {status}")
    if outcome.metrics_path:
        print(f"  {c('metrics:', '90')} {outcome.metrics_path}")


def cmd_scan(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    _apply_cli_overrides(config, args)

    print(c(f"aegis {__version__}", "1") + f"  policy: {describe(config)}")

    outcomes = run_many(
        args.images,
        config,
        write_reports=not args.no_report,
        persist=not args.no_store,
        send_notifications=not args.no_notify,
        export_metrics=not args.no_metrics,
        source=args.source,
    )

    if args.json:
        print(json.dumps([o.to_dict() for o in outcomes], indent=2))
    else:
        for outcome in outcomes:
            print_summary(outcome, config, quiet=args.quiet)

    if any(o.error for o in outcomes):
        return EXIT_OK if args.exit_zero else EXIT_SCAN_ERROR
    if any(not o.decision.passed for o in outcomes):
        return EXIT_OK if args.exit_zero else EXIT_POLICY_FAIL
    return EXIT_OK


# ------------------------------------------------------------- history ------


def cmd_history(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    _apply_cli_overrides(config, args)
    store = ScanStore(config.resolve(config.storage.database))

    since = None
    if args.days:
        since = (datetime.now(timezone.utc) - timedelta(days=args.days)).isoformat(timespec="seconds")
    rows = store.scans(image=args.image, since=since, limit=args.limit)
    if args.json:
        print(json.dumps(rows, indent=2))
        return EXIT_OK
    if not rows:
        print("no scans recorded yet — run `aegis scan <image>` first")
        return EXIT_OK

    print(f"{'SCANNED AT':<22} {'VERDICT':<8} {'CRIT':>4} {'HIGH':>5} {'MED':>5} {'LOW':>5}  IMAGE")
    for row in rows:
        verdict = row["verdict"] or "-"
        print(
            f"{row['scanned_at']:<22} "
            f"{c(verdict, '32' if verdict == 'PASS' else '31'):<8} "
            f"{row['critical']:>4} {row['high']:>5} {row['medium']:>5} {row['low']:>5}  {row['image']}"
        )
    return EXIT_OK


def cmd_images(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    _apply_cli_overrides(config, args)
    store = ScanStore(config.resolve(config.storage.database))
    rows = store.images()
    if args.json:
        print(json.dumps(rows, indent=2))
        return EXIT_OK

    summary = store.summary()
    print(
        f"{summary['images_tracked']} image(s) · {summary['total_scans']} scan(s) · "
        f"{summary['critical']} critical · {summary['high']} high · "
        f"{summary['failing_images']} failing"
    )
    print(f"\n{'IMAGE':<44} {'VERDICT':<8} {'CRIT':>4} {'HIGH':>5} {'FIX':>5} {'SIZE':>9}  LAST SCAN")
    for row in rows:
        verdict = row["verdict"] or "-"
        print(
            f"{row['image'][:43]:<44} "
            f"{c(verdict, '32' if verdict == 'PASS' else '31'):<8} "
            f"{row['critical']:>4} {row['high']:>5} {row['fixable']:>5} "
            f"{human_size(row['image_size_bytes']):>9}  {row['scanned_at']}"
        )
    return EXIT_OK


def cmd_rescan(args: argparse.Namespace) -> int:
    """Re-scan images whose last result is older than the staleness window.

    CVE databases change daily, so an image that passed last week is not
    necessarily clean today -- this is what a nightly cron calls.
    """
    config = load_config(args.config)
    _apply_cli_overrides(config, args)
    store = ScanStore(config.resolve(config.storage.database))

    hours = args.stale_hours if args.stale_hours is not None else config.rescan.stale_after_hours
    targets = [row["image"] for row in store.stale_images(hours)]
    for image in config.rescan.images:
        if image not in targets:
            # Configured images are always eligible, even if never scanned before.
            if not store.latest_scan(image):
                targets.append(image)
    if args.image:
        targets = [img for img in targets if args.image in img]

    if not targets:
        print(f"nothing to rescan (no image older than {hours}h)")
        return EXIT_OK

    print(f"rescanning {len(targets)} stale image(s) (older than {hours}h)")
    outcomes = run_many(
        targets,
        config,
        write_reports=not args.no_report,
        send_notifications=not args.no_notify,
        source="rescan",
    )
    for outcome in outcomes:
        print_summary(outcome, config, quiet=args.quiet)
    if any(o.error for o in outcomes):
        return EXIT_SCAN_ERROR
    return EXIT_POLICY_FAIL if any(not o.decision.passed for o in outcomes) else EXIT_OK


def cmd_purge(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    _apply_cli_overrides(config, args)
    store = ScanStore(config.resolve(config.storage.database))
    days = args.days if args.days is not None else config.storage.retention_days
    removed = store.purge_older_than(days)
    print(f"removed {removed} scan(s) older than {days} day(s)")
    return EXIT_OK


# ---------------------------------------------------------- exceptions ------


def cmd_exceptions(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    _apply_cli_overrides(config, args)
    path = config.resolve(config.exceptions.file)
    try:
        store = ExceptionStore.load(path)
    except ExceptionError as exc:
        print(c(f"invalid exceptions file: {exc}", "31"), file=sys.stderr)
        return EXIT_USAGE

    action = args.exceptions_action
    if action == "list":
        if args.json:
            print(json.dumps([e.to_dict() for e in store.entries], indent=2))
            return EXIT_OK
        if not store.entries:
            print(f"no exceptions defined ({path})")
            return EXIT_OK
        print(f"{len(store)} exception(s) in {path}\n")
        print(f"{'CVE':<20} {'PACKAGE':<22} {'IMAGE':<26} {'EXPIRES':<12} {'DAYS':>5}  REASON")
        for entry in sorted(store.entries, key=lambda e: e.expires):
            days = entry.days_remaining()
            flag = "31" if days < 0 else ("33" if days <= config.exceptions.warn_on_expiring_within_days else "32")
            print(
                f"{entry.vuln_id:<20} {entry.package[:21]:<22} {entry.image[:25]:<26} "
                f"{entry.expires.isoformat():<12} {c(f'{days:>5}', flag)}  {entry.reason[:48]}"
            )
        return EXIT_OK

    if action == "add":
        expires = None
        if args.expires:
            try:
                expires = datetime.strptime(args.expires, "%Y-%m-%d").date()
            except ValueError:
                print(c("--expires must be YYYY-MM-DD", "31"), file=sys.stderr)
                return EXIT_USAGE
        elif args.days:
            expires = date.today() + timedelta(days=args.days)
        entry = store.add(
            args.cve,
            args.reason,
            expires=expires,
            default_expiry_days=config.exceptions.default_expiry_days,
            package=args.package,
            image=args.image,
            approved_by=args.approved_by,
            ticket=args.ticket,
        )
        store.save(path)
        print(f"added exception for {entry.vuln_id} (expires {entry.expires.isoformat()}) → {path}")
        return EXIT_OK

    if action == "remove":
        removed = store.remove(args.cve, image=args.image, package=args.package)
        store.save(path)
        print(f"removed {removed} exception(s) for {args.cve}")
        return EXIT_OK if removed else EXIT_USAGE

    if action == "prune":
        expired = store.prune_expired()
        if args.dry_run:
            print(f"{len(expired)} expired exception(s) would be removed")
            for entry in expired:
                print(f"  {entry.vuln_id} (expired {entry.expires.isoformat()})")
            return EXIT_OK
        store.save(path)
        print(f"pruned {len(expired)} expired exception(s)")
        return EXIT_OK

    return EXIT_USAGE


# ------------------------------------------------------------- serve -------


def cmd_serve(args: argparse.Namespace) -> int:
    from .dashboard import create_app

    config = load_config(args.config)
    _apply_cli_overrides(config, args)
    app = create_app(config)
    print(f"aegis dashboard on http://{args.host}:{args.port}  (db: {config.resolve(config.storage.database)})")
    app.run(host=args.host, port=args.port, debug=args.debug)
    return EXIT_OK


def cmd_doctor(args: argparse.Namespace) -> int:
    """Check that everything the tool needs is actually present."""
    config = load_config(args.config)
    ok = True

    def check(label: str, passed: bool, detail: str = "") -> None:
        nonlocal ok
        mark = c("✓", "32") if passed else c("✗", "31")
        print(f" {mark} {label}" + (f" — {detail}" if detail else ""))
        ok = ok and passed

    print(c("aegis doctor", "1"))
    config_path = config.source_path or "(defaults — no aegis.yml found)"
    check("config file", True, config_path)

    try:
        scanner = get_scanner(config)
        version = scanner.version()
        check(f"{config.scanner.engine} binary", version != "unknown", f"version {version}")
    except ScannerNotInstalled as exc:
        check("scanner binary", False, str(exc))
    except ScannerError as exc:
        check("scanner engine", False, str(exc))

    db_path = config.resolve(config.storage.database)
    try:
        store = ScanStore(db_path)
        summary = store.summary()
        check("history database", True, f"{db_path} ({summary['total_scans']} scans)")
    except Exception as exc:
        check("history database", False, f"{db_path}: {exc}")

    exceptions_path = config.resolve(config.exceptions.file)
    try:
        store_ex = ExceptionStore.load(exceptions_path)
        expired = store_ex.expired()
        detail = f"{len(store_ex)} entries"
        if expired:
            detail += f", {len(expired)} expired (run `aegis exceptions prune`)"
        check("exceptions file", True, detail)
    except ExceptionError as exc:
        check("exceptions file", False, str(exc))

    reports_dir = config.resolve(config.reporting.output_dir)
    try:
        reports_dir.mkdir(parents=True, exist_ok=True)
        probe = reports_dir / ".aegis-write-test"
        probe.write_text("ok")
        probe.unlink()
        check("reports directory writable", True, str(reports_dir))
    except OSError as exc:
        check("reports directory writable", False, f"{reports_dir}: {exc}")

    check("policy", True, describe(config))
    for name, settings in (
        ("slack", config.notifications.slack),
        ("teams", config.notifications.teams),
    ):
        if settings.enabled:
            import os

            check(
                f"{name} webhook env",
                bool(os.environ.get(settings.webhook_url_env)),
                f"${settings.webhook_url_env}",
            )
    return EXIT_OK if ok else EXIT_USAGE


# -------------------------------------------------------------- parser ------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="Container image vulnerability scanner with CI gating, reporting and history.",
    )
    parser.add_argument("--version", action="version", version=f"aegis {__version__}")
    parser.add_argument("-c", "--config", help="path to aegis.yml")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="-v info, -vv debug")
    parser.add_argument("-q", "--quiet", action="store_true", help="only print the essentials")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(sp: argparse.ArgumentParser) -> None:
        # SUPPRESS so that passing -q after the subcommand does not clobber the
        # global flag's value with the subparser default.
        sp.add_argument(
            "-q", "--quiet", action="store_true", default=argparse.SUPPRESS,
            help="only print the essentials",
        )
        sp.add_argument("--db", help="override the history database path")
        sp.add_argument("--exceptions-file", help="override the exceptions file path")
        sp.add_argument("--json", action="store_true", help="machine-readable output")

    # scan
    scan = sub.add_parser("scan", help="scan one or more images and apply the gate policy")
    scan.add_argument("images", nargs="+", metavar="IMAGE")
    scan.add_argument("--fail-on", choices=[s.value for s in Severity], help="severity floor that fails the build")
    scan.add_argument("--max-critical", type=int, help="tolerated CRITICAL findings")
    scan.add_argument("--max-high", type=int, help="tolerated HIGH findings")
    scan.add_argument("--max-medium", type=int, help="tolerated MEDIUM findings")
    scan.add_argument("--max-low", type=int, help="tolerated LOW findings")
    scan.add_argument("--max-total", type=int, help="tolerated total findings")
    scan.add_argument("--warn-only", action="store_true", help="report breaches without failing")
    scan.add_argument("--fixable-only", action="store_true", help="only count findings that have a fix")
    scan.add_argument("--ignore-unfixed", action="store_true", help="ask the scanner to skip unfixed CVEs")
    scan.add_argument("--offline", action="store_true", help="never update the vulnerability DB")
    scan.add_argument("--severity", help="severities to collect, e.g. HIGH,CRITICAL")
    scan.add_argument("--format", help="report formats: json,html,markdown")
    scan.add_argument("-o", "--output-dir", help="where to write reports")
    scan.add_argument("--source", default="cli", help="label recorded in history (cli, github-actions, jenkins…)")
    scan.add_argument("--no-report", action="store_true")
    scan.add_argument("--no-store", action="store_true")
    scan.add_argument("--no-notify", action="store_true")
    scan.add_argument("--no-metrics", action="store_true")
    scan.add_argument("--exit-zero", action="store_true", help="always exit 0 (observe mode)")
    add_common(scan)
    scan.set_defaults(func=cmd_scan)

    # history
    history = sub.add_parser("history", help="list past scans")
    history.add_argument("--image", help="filter by image (glob with *)")
    history.add_argument("--days", type=int, help="only scans from the last N days")
    history.add_argument("--limit", type=int, default=25)
    add_common(history)
    history.set_defaults(func=cmd_history)

    # images
    images = sub.add_parser("images", help="latest result per tracked image")
    add_common(images)
    images.set_defaults(func=cmd_images)

    # rescan
    rescan = sub.add_parser("rescan", help="re-scan images whose last result is stale")
    rescan.add_argument("--stale-hours", type=int, help="staleness window (default from config)")
    rescan.add_argument("--image", help="only rescan images containing this substring")
    rescan.add_argument("--no-report", action="store_true")
    rescan.add_argument("--no-notify", action="store_true")
    add_common(rescan)
    rescan.set_defaults(func=cmd_rescan)

    # purge
    purge = sub.add_parser("purge", help="delete scans older than the retention window")
    purge.add_argument("--days", type=int)
    add_common(purge)
    purge.set_defaults(func=cmd_purge)

    # exceptions
    exceptions = sub.add_parser("exceptions", help="manage approved vulnerability exceptions")
    ex_sub = exceptions.add_subparsers(dest="exceptions_action", required=True)

    ex_list = ex_sub.add_parser("list", help="show all exceptions")
    add_common(ex_list)

    ex_add = ex_sub.add_parser("add", help="approve a vulnerability for a bounded period")
    ex_add.add_argument("cve", help="CVE id, or * for any")
    ex_add.add_argument("--reason", required=True, help="why this is acceptable")
    ex_add.add_argument("--package", default="*", help="package glob this applies to")
    ex_add.add_argument("--image", default="*", help="image glob this applies to")
    ex_add.add_argument("--expires", help="expiry date YYYY-MM-DD")
    ex_add.add_argument("--days", type=int, help="expire N days from today")
    ex_add.add_argument("--approved-by", default="", help="who signed off")
    ex_add.add_argument("--ticket", default="", help="tracking ticket")
    add_common(ex_add)

    ex_rm = ex_sub.add_parser("remove", help="delete an exception")
    ex_rm.add_argument("cve")
    ex_rm.add_argument("--package", default="*")
    ex_rm.add_argument("--image", default="*")
    add_common(ex_rm)

    ex_prune = ex_sub.add_parser("prune", help="drop expired exceptions")
    ex_prune.add_argument("--dry-run", action="store_true")
    add_common(ex_prune)

    exceptions.set_defaults(func=cmd_exceptions)

    # serve
    serve = sub.add_parser("serve", help="run the web dashboard")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--debug", action="store_true")
    add_common(serve)
    serve.set_defaults(func=cmd_serve)

    # doctor
    doctor = sub.add_parser("doctor", help="verify the local setup")
    add_common(doctor)
    doctor.set_defaults(func=cmd_doctor)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(args.verbose, args.quiet)
    try:
        return int(args.func(args))
    except ScannerNotInstalled as exc:
        print(c(f"error: {exc}", "31"), file=sys.stderr)
        return EXIT_USAGE
    except ScannerError as exc:
        print(c(f"scan error: {exc}", "31"), file=sys.stderr)
        return EXIT_SCAN_ERROR
    except FileNotFoundError as exc:
        print(c(f"error: {exc}", "31"), file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
