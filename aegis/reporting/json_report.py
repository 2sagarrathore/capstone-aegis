"""Machine-readable report -- the format other tooling should consume."""

from __future__ import annotations

import json
from typing import Any

from ..config import AegisConfig
from ..models import PolicyDecision, ScanResult


def render_json(
    result: ScanResult,
    decision: PolicyDecision,
    config: AegisConfig,
    diff: Any | None = None,
) -> str:
    from ..policy import describe

    payload: dict[str, Any] = result.to_dict()
    payload["policy"] = {"description": describe(config), **decision.to_dict()}
    if diff is not None:
        payload["diff"] = diff.to_dict()
    return json.dumps(payload, indent=2) + "\n"
