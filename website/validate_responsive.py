#!/usr/bin/env python3
"""Fail closed on Security Center responsive/public-document layout regressions."""

from pathlib import Path
import sys

CSS = Path(__file__).resolve().parent / "site.css"


def main() -> int:
    errors: list[str] = []
    css = CSS.read_text(encoding="utf-8")

    required = {
        "public header remains in normal document flow": ".site-header{position:relative;inset-block-start:auto}",
        "tablet navigation becomes a three-column touch grid": "@media(max-width:940px){:root{--header-offset:24px}.nav-wrap nav{display:grid;grid-template-columns:repeat(3,minmax(0,1fr))",
        "phone navigation becomes two columns": "@media(max-width:620px){:root{--header-offset:24px}.nav-wrap{gap:10px 12px}.nav-wrap nav{grid-template-columns:repeat(2,minmax(0,1fr))",
        "narrow phone navigation becomes one column": "@media(max-width:390px){.nav-wrap{grid-template-columns:1fr auto}.nav-wrap nav{grid-column:1/-1;grid-row:2;grid-template-columns:1fr}",
        "content grids collapse to one column on phones": ".card-grid,.split,.state-grid{grid-template-columns:1fr}",
        "tablet state grid is readable": ".state-grid{grid-template-columns:repeat(2,1fr)}",
        "public anchors no longer reserve sticky-header space": ":root{--header-offset:24px}",
    }
    for label, marker in required.items():
        if marker not in css:
            errors.append(f"Missing responsive contract: {label}")

    sticky = css.rfind(".site-header{position:sticky")
    normal_flow = css.rfind(".site-header{position:relative;inset-block-start:auto}")
    if sticky >= 0 and normal_flow <= sticky:
        errors.append("Final Security Center cascade does not override sticky public navigation with normal-flow navigation")

    if errors:
        print("Security Center responsive validation failed:")
        for error in errors:
            print(f"  - {error}")
        return 1

    print("Security Center responsive layout validation passed: normal-flow header, 3/2/1-column navigation, single-column phone content, and compact anchor offsets are protected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
