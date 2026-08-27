#!/usr/bin/env python3
"""Collect data-minimized Wardveil ClamAV runtime health evidence."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.wardveil_clamav import ClamAVClient  # noqa: E402
from reference.wardveil_clamav_runtime import (  # noqa: E402
    collect_clamav_health,
    config_from_env,
    policy_from_env,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--status-record",
        action="store_true",
        help="emit the normalized Wardveil status presentation record instead of raw component health evidence",
    )
    parser.add_argument(
        "--require-healthy",
        action="store_true",
        help="return a non-zero status when clean verdicts are not currently eligible",
    )
    args = parser.parse_args()

    try:
        client = ClamAVClient(config_from_env())
        health = collect_clamav_health(client, policy=policy_from_env())
    except (TypeError, ValueError) as exc:
        print(f"Wardveil ClamAV health configuration error: {exc.__class__.__name__}", file=sys.stderr)
        return 2

    payload = health.as_status_record() if args.status_record else health.as_dict()
    print(json.dumps(payload, sort_keys=True, indent=2))
    if args.require_healthy and not health.clean_verdicts_eligible:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
