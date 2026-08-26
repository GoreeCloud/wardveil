#!/usr/bin/env python3
"""Validate the canonical Wardveil first-party capability contract."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "wardveil.capabilities.json"
EXPECTED_VERSION = "0.1.0"
EXPECTED_FOUNDATION = "0.8.0"
EXPECTED = {
    "trust": "Wardveil Trust",
    "protect": "Wardveil Protect",
    "detect": "Wardveil Detect",
    "scan": "Wardveil Scan",
    "policy": "Wardveil Policy",
    "quarantine": "Wardveil Quarantine",
    "audit": "Wardveil Audit",
    "response": "Wardveil Response",
    "security_center": "Wardveil Security Center",
}
EXPECTED_LIFECYCLE = ["trust", "policy", "protect", "detect", "scan", "quarantine", "response", "audit"]


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    if not CONTRACT.is_file():
        fail("missing contracts/wardveil.capabilities.json")
    data = json.loads(CONTRACT.read_text(encoding="utf-8"))
    if data.get("contract_version") != EXPECTED_VERSION:
        fail("unexpected capability contract version")
    if data.get("foundation_version") != EXPECTED_FOUNDATION:
        fail("capability contract foundation version is inconsistent")
    if data.get("umbrella") != "Wardveil Security":
        fail("Wardveil Security must remain the umbrella system")

    capabilities = data.get("capabilities")
    if not isinstance(capabilities, list):
        fail("capabilities must be a list")
    mapped = {item.get("id"): item for item in capabilities if isinstance(item, dict)}
    if set(mapped) != set(EXPECTED):
        fail("canonical Wardveil capability set is incomplete or contains unknown entries")
    for capability_id, expected_name in EXPECTED.items():
        item = mapped[capability_id]
        if item.get("name") != expected_name:
            fail(f"unexpected name for capability {capability_id}")
        if not item.get("responsibility"):
            fail(f"missing responsibility for capability {capability_id}")
        if not item.get("authoritative_for"):
            fail(f"missing authority declaration for capability {capability_id}")

    if data.get("representative_lifecycle") != EXPECTED_LIFECYCLE:
        fail("representative lifecycle has drifted from the canonical architecture")

    cross = data.get("cross_cutting")
    required_true = (
        "security_center_spans_lifecycle",
        "evidence_before_reassurance",
        "least_privilege",
        "data_minimization",
        "conservative_aggregation",
        "verifiable_public_claims",
        "branding_alone_is_not_integration",
    )
    if not isinstance(cross, dict) or any(cross.get(key) is not True for key in required_true):
        fail("cross-cutting Wardveil security invariants are incomplete")

    print("Wardveil capability contract validation passed.")


if __name__ == "__main__":
    main()
