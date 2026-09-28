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
GOVERNANCE = ROOT / "REPOSITORY-GOVERNANCE.md"
SECURITY = ROOT / "SECURITY.md"
LICENSE = ROOT / "LICENSE"
README = ROOT / "README.md"
VERSION = ROOT / "VERSION"
RUNNER = "ubuntu-24.04"

REQUIRED_ROOT_FILES = (
    "README.md",
    "SPECIFICATIONS.md",
    "FEATURES.md",
    "IMPLEMENTED-FEATURES.md",
    "PLANNED-FEATURES.md",
    "CHANGELOGS.md",
    "BENEFITS.md",
    "COMPETITIVE-OBJECTIVES.md",
    "BRANDING.md",
    "USER-MANUAL.md",
    "PRIVACY POLICY.md",
    "NOTES.md",
    "SECURITY.md",
    ".gitignore",
    ".editorconfig",
    "goreecloud.platform.yaml",
)
REQUIRED_REPOSITORY_CONTROLS = (".github/PULL_REQUEST_TEMPLATE.md",)
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

    release_line = f"> **Current status:** Foundation {match.group(1)}.{match.group(2)} active."
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
        "SECURITY.md @GoreeCloud",
        "PRIVACY POLICY.md @GoreeCloud",
        "LICENSE @GoreeCloud",
        "REPOSITORY-GOVERNANCE.md @GoreeCloud",
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
