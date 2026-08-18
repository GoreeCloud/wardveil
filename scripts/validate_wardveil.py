#!/usr/bin/env python3
"""Validate the Wardveil Security repository foundation using only the Python standard library."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = (
    "README.md",
    "IDENTITY.md",
    "ICON.md",
    "INTEGRATION.md",
    "CONFORMANCE.md",
    "VERSION",
    "contracts/wardveil.identity.json",
)

APPROVED_NAMES = (
    "Wardveil Security by GoreeCloud",
    "Wardveil Security",
    "Wardveil",
    "Protected by Wardveil",
)

RESERVED_NAMES = (
    "Wardveil Access",
    "Wardveil Network",
    "Wardveil Integrity",
    "Wardveil Threats",
    "Wardveil Verify",
    "Wardveil Watch",
    "Wardveil Security Center",
)

CANONICAL_ICON_PATH = "branding/wardveil-security-icon.svg"


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    missing = [path for path in REQUIRED_FILES if not (ROOT / path).is_file()]
    if missing:
        fail(f"missing required files: {', '.join(missing)}")

    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    if version != "0.1.0":
        fail(f"unexpected foundation version: {version!r}")

    contract_path = ROOT / "contracts/wardveil.identity.json"
    try:
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {contract_path.relative_to(ROOT)}: {exc}")

    identity = contract.get("identity")
    if not isinstance(identity, dict):
        fail("identity contract must contain an identity object")

    expected = {
        "full_presentation": APPROVED_NAMES[0],
        "primary_name": APPROVED_NAMES[1],
        "short_name": APPROVED_NAMES[2],
        "protection_phrase": APPROVED_NAMES[3],
    }
    if identity != expected:
        fail("machine-readable approved identity does not match the canonical naming contract")

    if contract.get("technical_authority") is not False:
        fail("Wardveil must not be marked as the underlying technical authority")

    reserved = contract.get("reserved_unapproved_component_names")
    if reserved != list(RESERVED_NAMES):
        fail("reserved Wardveil component-name list changed without a foundation update")

    if contract.get("legal_status") != (
        "internal-naming-approved-external-name-conflict-and-legal-clearance-pending"
    ):
        fail("legal status must remain explicit and fail closed while external clearance is pending")

    visual = contract.get("visual_identity")
    if not isinstance(visual, dict):
        fail("identity contract must contain visual_identity metadata")

    if visual.get("description_document") != "ICON.md":
        fail("ICON.md must remain the canonical Wardveil icon-description contract")

    if visual.get("canonical_asset_path") != CANONICAL_ICON_PATH:
        fail("canonical Wardveil icon path changed without a foundation update")

    visual_status = visual.get("canonical_visual_identity_status")
    showcase_status = visual.get("showcase_status")
    icon_exists = (ROOT / CANONICAL_ICON_PATH).is_file()

    if visual_status == "pending-canonical-icon":
        if showcase_status != "blocked-pending-canonical-icon":
            fail("showcase must remain blocked while the canonical Wardveil icon is pending")
        if icon_exists:
            fail("canonical icon asset exists but visual identity is still marked pending; approve and reconcile status explicitly")
    elif visual_status == "approved":
        if showcase_status != "approved":
            fail("approved canonical icon requires an explicitly approved showcase status")
        if not icon_exists:
            fail(f"approved visual identity requires {CANONICAL_ICON_PATH}")
    else:
        fail(f"unsupported canonical visual identity status: {visual_status!r}")

    if visual.get("temporary_icon_substitution_allowed") is not False:
        fail("temporary icon substitution must remain disallowed")

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    identity_doc = (ROOT / "IDENTITY.md").read_text(encoding="utf-8")
    icon_doc = (ROOT / "ICON.md").read_text(encoding="utf-8")
    conformance = (ROOT / "CONFORMANCE.md").read_text(encoding="utf-8")

    for name in APPROVED_NAMES:
        if name not in readme and name not in identity_doc:
            fail(f"approved identity term is missing from canonical documentation: {name}")

    if "external name-conflict" not in readme.lower():
        fail("README must preserve the external name-conflict clearance boundary")

    if "technical authority" not in conformance.lower():
        fail("CONFORMANCE.md must preserve the technical-authority boundary")

    if "two softly curved, layered veil panels" not in icon_doc:
        fail("ICON.md must preserve the canonical Wardveil icon concept")

    if "not visually showcase-ready" not in icon_doc.lower():
        fail("ICON.md must preserve the fail-closed showcase gate")

    print("Wardveil Security foundation validation passed.")


if __name__ == "__main__":
    main()
