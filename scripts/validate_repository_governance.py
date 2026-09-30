#!/usr/bin/env python3
"""Validate source-controlled Wardveil repository-governance controls."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/validate.yml"
DEPENDABOT = ROOT / ".github/dependabot.yml"
CODEOWNERS = ROOT / ".github/CODEOWNERS"
GOVERNANCE = ROOT / "docs/REPOSITORY-GOVERNANCE.md"
SECURITY = ROOT / "docs/SECURITY.md"
LICENSE = ROOT / "LICENSE"
README = ROOT / "README.md"
VERSION = ROOT / "VERSION"
RUNNER = "ubuntu-24.04"

REQUIRED_ROOT_FILES = (
    "README.md",
    "docs/README.md",
    "docs/PROJECT-SPECIFICATIONS.md",
    "docs/PROJECT-RECORD.md",
    "docs/FEATURES.md",
    "docs/IMPLEMENTED-FEATURES.md",
    "docs/PLANNED-FEATURES.md",
    "docs/CHANGELOGS.md",
    "docs/BENEFITS.md",
    "docs/COMPETITIVE-OBJECTIVES.md",
    "docs/BRANDING.md",
    "docs/USER-MANUAL.md",
    "docs/PRIVACY POLICY.md",
    "docs/NOTES.md",
    "docs/SECURITY.md",
    ".gitignore",
    ".editorconfig",
    "goreecloud.platform.yaml",
)
REQUIRED_REPOSITORY_CONTROLS = (".github/PULL_REQUEST_TEMPLATE.md",)
RETIRED_ROOT_FILES = ("SPECIFICATIONS.md", "FEATURE-ROADMAP.md")
PROHIBITED_ROOT_DOCUMENTS = (
    "ADOPTION.md",
    "AGGREGATION.md",
    "ARCHITECTURE.md",
    "AUDIT-EVIDENCE-LEDGER-V2.md",
    "BENEFITS.md",
    "BRANDING.md",
    "CAPABILITIES.md",
    "CHANGELOG.md",
    "CHANGELOGS.md",
    "CLAMAV-INTEGRATION.md",
    "CLOUDFLARE-ACCEPTANCE-PROBE.md",
    "CLOUDFLARE-DEPLOYMENT.md",
    "CLOUDFLARE-PERSISTENCE.md",
    "CLOUDFLARE-RUNTIME-EVIDENCE-COLLECTION.md",
    "CLOUDFLARE-RUNTIME-OPERATIONS.md",
    "COMPATIBILITY.md",
    "COMPETITIVE-OBJECTIVES.md",
    "CONFORMANCE.md",
    "DETECT-SCAN-SDK.md",
    "DETECTION-ENGINE-V1.md",
    "DURABLE-RECORDS.md",
    "EVERKEEP-RESTORE-VERIFICATION.md",
    "EXECUTION-RECONCILIATION.md",
    "EXECUTION-STATE.md",
    "FEATURES.md",
    "ICON-REVIEW.md",
    "ICON.md",
    "IDENTITY-KEY-LIFECYCLE-V1.md",
    "IDENTITY.md",
    "IMPLEMENTED-FEATURES.md",
    "INCIDENT-CENTER-V1.md",
    "INCIDENT-CONTROL.md",
    "INCIDENT-PLANE-V2.md",
    "INTEGRATION-PIPELINE.md",
    "INTEGRATION.md",
    "MANAGER-INTEGRATION.md",
    "MESH-EVIDENCE.md",
    "MESH-TRANSPORT.md",
    "NOTES.md",
    "OBSERVABILITY-INTEGRATION.md",
    "PERSISTENCE.md",
    "PLANNED-FEATURES.md",
    "PLATFORM-ADOPTION-AND-REPOSITORY-GOVERNANCE-V1.md",
    "PLATFORM-API.md",
    "PLATFORM-POLICY-INTEGRATION.md",
    "POLICY-DECISION-AND-ENFORCEMENT-V2.md",
    "POLICY-EXECUTION-BRIDGE-V1.md",
    "PRIVACY POLICY.md",
    "PRIVACY-SHIELD.md",
    "PROJECT-RECORD.md",
    "PROJECT-SPECIFICATIONS.md",
    "PROTECT-SDK.md",
    "PROTECTION-COVERAGE-REGISTRY.md",
    "QUARANTINE-EXECUTOR.md",
    "QUARANTINE-OBJECT-V2.md",
    "REPOSITORY-GOVERNANCE.md",
    "RUNTIME-ACCEPTANCE-EVIDENCE.md",
    "RUNTIME-AUTHORIZATION.md",
    "RUNTIME-CONTRACTS.md",
    "SECURITY-CENTER-V2.md",
    "SECURITY-CENTER.md",
    "SECURITY-STATE-V2.md",
    "SECURITY.md",
    "SEMANTIC-COLOR.md",
    "SERVICE-IDENTITY.md",
    "STATUS.md",
    "THREAT-MODEL.md",
    "TRUST-POLICY-SDK.md",
    "TRUST-SESSION-DEVICE-POSTURE-V2.md",
    "USER-MANUAL.md",
)
MINIMUM_MEANINGFUL_CHARACTERS = 20

ACTION_PIN_PATTERN = re.compile(
    r"uses:\s+(actions/(?:checkout|setup-python))@([0-9a-f]{40})\s+#\s+(v\d+\.\d+\.\d+)"
)
EXPECTED_ACTIONS = {"actions/checkout", "actions/setup-python"}


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def read(path: Path) -> str:
    if not path.is_file():
        fail(f"required repository-governance file missing: {path.relative_to(ROOT)}")
    return path.read_text(encoding="utf-8")


def require(text: str, token: str, context: str) -> None:
    if token not in text:
        fail(f"{context} missing required control: {token}")


def validate_action_pins(workflow: str) -> None:
    matches = ACTION_PIN_PATTERN.findall(workflow)
    action_names = [name for name, _, _ in matches]

    for action in EXPECTED_ACTIONS:
        count = action_names.count(action)
        if count != 1:
            fail(f"validation workflow must contain exactly one immutable annotated pin for {action}; found {count}")

    unexpected = set(action_names) - EXPECTED_ACTIONS
    if unexpected:
        fail(f"validation workflow contains unexpected governed Action pins: {sorted(unexpected)}")

    for action in EXPECTED_ACTIONS:
        loose_refs = re.findall(rf"uses:\s+{re.escape(action)}@([^\s#]+)", workflow)
        if len(loose_refs) != 1:
            fail(f"validation workflow must contain exactly one reference for {action}")
        if not re.fullmatch(r"[0-9a-f]{40}", loose_refs[0]):
            fail(f"validation workflow reference for {action} is not an immutable 40-character commit SHA")


def validate_license(license_text: str) -> None:
    for phrase in (
        "MIT License",
        "Copyright (c) 2026 LaDamian Goree / GoreeCloud",
        "Permission is hereby granted, free of charge",
        "THE SOFTWARE IS PROVIDED \"AS IS\"",
    ):
        require(license_text, phrase, "LICENSE")


def validate_readme_release_status(readme: str, version_text: str) -> None:
    version = version_text.strip()
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", version)
    if not match:
        fail("VERSION must contain exactly one semantic version")

    require(
        readme,
        "> **Current status:** Weave under Platform Contract 2.0;",
        "README lifecycle status",
    )
    release_line = f"Foundation {match.group(1)}.{match.group(2)} is the active source/runtime line."
    require(readme, release_line, "README release status")

    if re.search(r"> \*\*Current status:\*\* Foundation \d+\.\d+ development\.", readme):
        fail("README release status still identifies an accepted foundation as development")

    require(
        readme,
        "README current-status declaration synchronized",
        "README release discipline",
    )


def main() -> None:
    for relative in (*REQUIRED_ROOT_FILES, *REQUIRED_REPOSITORY_CONTROLS):
        text = read(ROOT / relative).strip()
        if len(text) < MINIMUM_MEANINGFUL_CHARACTERS:
            fail(f"required repository control is empty/placeholder-sized: {relative}")
        if text.lower() in {"todo", "tbd", "placeholder", "coming soon"}:
            fail(f"required repository control is a placeholder: {relative}")

    for relative in PROHIBITED_ROOT_DOCUMENTS:
        path = ROOT / relative
        if path.exists() or path.is_symlink():
            fail(f"human-readable repository documentation must live under docs/: {relative}")

    for relative in RETIRED_ROOT_FILES:
        path = ROOT / relative
        if path.exists() or path.is_symlink():
            fail(f"retired competing repository control must not exist: {relative}")

    for relative in (
        ".github/workflows/validate-policy-execution-bridge-v1.yml",
        ".github/workflows/validate-trust-posture-v2.yml",
    ):
        feature_workflow = read(ROOT / relative)
        if '"FEATURE-ROADMAP.md"' in feature_workflow:
            fail(f"{relative} still watches retired FEATURE-ROADMAP.md")
        for canonical_feature_record in (
            '"docs/IMPLEMENTED-FEATURES.md"',
            '"docs/PLANNED-FEATURES.md"',
        ):
            require(feature_workflow, canonical_feature_record, relative)

    workflow = read(WORKFLOW)
    dependabot = read(DEPENDABOT)
    codeowners = read(CODEOWNERS)
    governance = read(GOVERNANCE)
    security = read(SECURITY)
    license_text = read(LICENSE)
    readme = read(README)
    version_text = read(VERSION)

    require(workflow, "permissions:\n  contents: read", "validation workflow")
    require(workflow, "persist-credentials: false", "validation workflow")
    require(workflow, f"runs-on: {RUNNER}", "validation workflow")
    require(workflow, "github.event.pull_request.head.sha || github.sha", "validation workflow")
    require(workflow, "Verify exact source revision", "validation workflow")
    validate_action_pins(workflow)

    if "runs-on: ubuntu-latest" in workflow:
        fail("validation workflow contains floating ubuntu-latest runner label")

    mutable_action_refs = re.findall(r"uses:\s+actions/(?:checkout|setup-python)@v\d+", workflow)
    if mutable_action_refs:
        fail("validation workflow contains mutable major-tag GitHub Action references")

    require(dependabot, 'package-ecosystem: "github-actions"', "Dependabot configuration")
    require(dependabot, 'directory: "/"', "Dependabot configuration")
    require(dependabot, 'interval: "weekly"', "Dependabot configuration")
    require(dependabot, "open-pull-requests-limit: 5", "Dependabot configuration")

    for ownership_rule in (
        "* @GoreeCloud",
        ".github/ @GoreeCloud",
        "docs/SECURITY.md @GoreeCloud",
        "docs/PRIVACY POLICY.md @GoreeCloud",
        "LICENSE @GoreeCloud",
        "docs/REPOSITORY-GOVERNANCE.md @GoreeCloud",
        "contracts/ @GoreeCloud",
        "branding/ @GoreeCloud",
        "website/ @GoreeCloud",
    ):
        require(codeowners, ownership_rule, "CODEOWNERS")

    for phrase in (
        "must be protected by GitHub branch protection or an equivalent repository ruleset",
        "material changes reach `main` through pull requests",
        "Validate Wardveil foundation",
        "Wardveil is intentionally public",
        "private GoreeCloud repository inventory",
        "restricted operational evidence",
        "GitHub reports `main` as protected",
        "current-source remediation does **not** rewrite historical commits",
        "full immutable commit SHA",
        "human review",
    ):
        if phrase.lower() not in governance.lower():
            fail(f"repository governance document missing required boundary: {phrase}")

    for phrase in (
        "private GoreeCloud administrative channel",
        "must not contain",
        "Missing or stale evidence must fail closed",
    ):
        if phrase.lower() not in security.lower():
            fail(f"security policy missing required repository boundary: {phrase}")

    validate_license(license_text)
    validate_readme_release_status(readme, version_text)

    print("Wardveil repository governance validation passed.")


if __name__ == "__main__":
    main()
