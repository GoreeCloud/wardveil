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

CHECKOUT_SHA = "34e114876b0b11c390a56381ad16ebd13914f8d5"
SETUP_PYTHON_SHA = "a26af69be951a213d495a4c3e4e4022e16d87065"
RUNNER = "ubuntu-24.04"


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


def main() -> None:
    workflow = read(WORKFLOW)
    dependabot = read(DEPENDABOT)
    codeowners = read(CODEOWNERS)
    governance = read(GOVERNANCE)
    security = read(SECURITY)

    require(workflow, "permissions:\n  contents: read", "validation workflow")
    require(workflow, "persist-credentials: false", "validation workflow")
    require(workflow, f"runs-on: {RUNNER}", "validation workflow")
    require(workflow, f"actions/checkout@{CHECKOUT_SHA}", "validation workflow")
    require(workflow, f"actions/setup-python@{SETUP_PYTHON_SHA}", "validation workflow")
    require(workflow, "github.event.pull_request.head.sha || github.sha", "validation workflow")
    require(workflow, "Verify exact source revision", "validation workflow")

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
        "REPOSITORY-GOVERNANCE.md @GoreeCloud",
        "contracts/ @GoreeCloud",
        "branding/ @GoreeCloud",
        "website/ @GoreeCloud",
    ):
        require(codeowners, ownership_rule, "CODEOWNERS")

    for phrase in (
        "must be protected by GitHub branch protection or an equivalent repository ruleset",
        "require changes to reach `main` through a pull request",
        "require the Wardveil validation workflow to pass before merge",
        "GitHub reports `main` as unprotected",
        "do not substitute for branch protection",
        "Issue #34",
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

    print("Wardveil repository governance validation passed.")


if __name__ == "__main__":
    main()
