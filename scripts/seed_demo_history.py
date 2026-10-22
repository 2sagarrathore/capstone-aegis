#!/usr/bin/env python3
"""Backfill plausible *demo* history into the Aegis database.

Aegis records history as scans happen, so a freshly installed instance has a
single day of data and the trend charts have nothing to draw.  This script
replays the real findings of each already-scanned image backwards in time,
dropping and re-adding findings so the trend shows how a backlog actually
behaves: new CVEs appear, patched ones disappear.

The rows are clearly labelled ``source='demo-seed'`` and can be removed with::

    sqlite3 aegis.db "DELETE FROM findings WHERE scan_id IN \\
      (SELECT scan_id FROM scans WHERE source='demo-seed'); \\
     DELETE FROM scans WHERE source='demo-seed';"

Do not run this against a database you report real numbers from.
"""

from __future__ import annotations

import argparse
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis.config import load_config  # noqa: E402
from aegis.models import PolicyDecision, ScanResult, Vulnerability  # noqa: E402
from aegis.storage import ScanStore  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--days", type=int, default=21, help="how far back to backfill")
    parser.add_argument("--every", type=int, default=2, help="days between simulated scans")
    parser.add_argument("--seed", type=int, default=11)
    parser.add_argument("--config", help="path to aegis.yml")
    args = parser.parse_args()

    random.seed(args.seed)
    config = load_config(args.config)
    store = ScanStore(config.resolve(config.storage.database))

    images = store.images()
    if not images:
        print("no scans to replay — run `aegis scan <image>` first", file=sys.stderr)
        return 1

    created = 0
    for row in images:
        findings = store.findings(row["scan_id"], include_suppressed=False)
        if not findings:
            continue
        pool = [Vulnerability.from_dict(f) for f in findings]

        for offset in range(args.days, 0, -args.every):
            # Fixed hour: a nightly scan runs at a set time, and randomising the
            # hour would spill some images into the previous calendar day and make
            # the daily bars look artificially uneven.
            when = (datetime.now(timezone.utc) - timedelta(days=offset)).replace(
                hour=3, minute=random.randint(0, 50), second=0, microsecond=0
            )
            # Older scans carry a slightly different backlog: a few of today's
            # findings had not been published yet, and a few extra were still open.
            keep = max(1, int(len(pool) * random.uniform(0.82, 1.0)))
            subset = random.sample(pool, keep)

            historical = ScanResult(
                image=row["image"],
                scanned_at=when.isoformat(timespec="seconds"),
                vulnerabilities=subset,
                image_digest=row["image_digest"],
                image_size_bytes=row["image_size_bytes"],
                os_family=row["os_family"],
                os_version=row["os_version"],
                scanner=row["scanner"],
                scanner_version=row["scanner_version"],
                duration_seconds=round(random.uniform(1.5, 9.0), 2),
            )
            counts = historical.counts()
            passed = counts["CRITICAL"] == 0 and counts["HIGH"] <= 10
            decision = PolicyDecision(
                passed=passed,
                reasons=[] if passed else [f"{counts['CRITICAL']} critical / {counts['HIGH']} high"],
            )
            store.record(historical, decision, source="demo-seed")
            created += 1

    print(f"seeded {created} historical scan(s) across {len(images)} image(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
