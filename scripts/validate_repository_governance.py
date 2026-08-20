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
RUNNER = "ubuntu-24.04"

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


def main() -> None:
    workflow = read(WORKFLOW)
    dependabot = read(DEPENDABOT)
    codeowners = read(CODEOWNERS)
    governance = read(GOVERNANCE)
    security = read(SECURITY)

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

    print("Wardveil repository governance validation passed.")


if __name__ == "__main__":
    main()
