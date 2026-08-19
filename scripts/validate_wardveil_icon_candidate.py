#!/usr/bin/env python3
"""Validate the Wardveil icon candidate without granting canonical approval."""

from __future__ import annotations

import sys
from pathlib import Path

from validate_wardveil_icon import ValidationError, validate_svg_file

ROOT = Path(__file__).resolve().parents[1]
CANDIDATE = ROOT / "branding/candidates/wardveil-security-icon.svg"
CANONICAL = ROOT / "branding/wardveil-security-icon.svg"


def main() -> int:
    if CANONICAL.exists():
        print("ERROR: canonical Wardveil icon exists during candidate-only validation", file=sys.stderr)
        return 1
    if not CANDIDATE.is_file():
        print("ERROR: Wardveil candidate icon is missing", file=sys.stderr)
        return 1
    try:
        validate_svg_file(CANDIDATE)
    except ValidationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print("Wardveil candidate SVG passes security and portability checks; canonical approval remains unchanged.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
