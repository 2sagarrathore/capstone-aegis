"""The build gate.

Given a :class:`ScanResult` that has already had exceptions applied, decide
whether the pipeline may continue.  Two independent rules can fail a build:

1. ``fail_on`` -- a severity floor.  Any finding at or above it fails.
2. ``max_allowed`` -- per-severity budgets, which *override* the floor for the
   severities they name.  ``{CRITICAL: 0, HIGH: 5}`` with ``fail_on: HIGH``
   means "no criticals at all, up to five highs tolerated".

``warn_only`` reports the same reasons but always passes, which is how you roll
the gate out to an existing pipeline without breaking every build on day one.
"""

from __future__ import annotations

import logging

from .config import AegisConfig
from .models import ALL_SEVERITIES, PolicyDecision, ScanResult, Severity

log = logging.getLogger("aegis.policy")


def evaluate(result: ScanResult, config: AegisConfig) -> PolicyDecision:
    policy = config.policy
    counts = result.counts()
    reasons: list[str] = []
    breached: list[str] = []

    budgeted = {k.upper(): v for k, v in (policy.max_allowed or {}).items()}
    floor = Severity.parse(policy.fail_on)

    for severity in ALL_SEVERITIES:
        name = severity.value
        relevant = [v for v in result.vulnerabilities if v.severity == severity]
        if policy.fail_on_fixable_only:
            relevant = [v for v in relevant if v.fixable]
        count = len(relevant)

        if name in budgeted:
            budget = budgeted[name]
            if count > budget:
                reasons.append(
                    f"{count} {name} finding(s) exceed the budget of {budget}"
                    + (" (fixable only)" if policy.fail_on_fixable_only else "")
                )
                breached.append(name)
            continue

        # No explicit budget: the severity floor applies.
        if severity >= floor and count > 0:
            reasons.append(
                f"{count} {name} finding(s) at or above the {floor.value} threshold"
                + (" (fixable only)" if policy.fail_on_fixable_only else "")
            )
            breached.append(name)

    if policy.max_total is not None and result.total > policy.max_total:
        reasons.append(
            f"{result.total} total finding(s) exceed max_total of {policy.max_total}"
        )

    if result.errors:
        reasons.append(f"scan reported {len(result.errors)} error(s)")

    passed = not reasons
    if not passed and policy.warn_only:
        log.warning(
            "policy breached for %s but warn_only is set -- not failing the build",
            result.image,
        )
        reasons.append("warn_only is enabled: reporting without failing the build")
        passed = True

    decision = PolicyDecision(passed=passed, reasons=reasons, breached_severities=breached)
    log.debug("policy verdict for %s: %s (%s)", result.image, decision.verdict, counts)
    return decision


def describe(config: AegisConfig) -> str:
    """One-line human summary of the active gate, printed in CI logs."""
    policy = config.policy
    parts = [f"fail_on>={policy.fail_on}"]
    if policy.max_allowed:
        budgets = ", ".join(
            f"{k.upper()}<={v}" for k, v in sorted(policy.max_allowed.items())
        )
        parts.append(f"budgets[{budgets}]")
    if policy.max_total is not None:
        parts.append(f"max_total<={policy.max_total}")
    if policy.fail_on_fixable_only:
        parts.append("fixable-only")
    if policy.warn_only:
        parts.append("WARN-ONLY")
    return " ".join(parts)
