#!/usr/bin/env python3
"""Fail closed on Security Center responsive/public-document layout regressions."""

from pathlib import Path
import sys

CSS = Path(__file__).resolve().parent / "site.css"


def main() -> int:
    errors: list[str] = []
    css = CSS.read_text(encoding="utf-8")

    required = {
        "public header remains in normal document flow": ".site-header{position:relative;z-index:20",
        "tablet navigation becomes a three-column touch grid": "@media(max-width:960px){.nav-wrap{grid-template-columns:1fr auto}.nav-wrap nav{grid-column:1/-1;grid-row:2;display:grid;grid-template-columns:repeat(3,minmax(0,1fr))",
        "phone navigation becomes two columns": "@media(max-width:640px){.shell{padding-inline:16px}.nav-wrap{gap:10px 12px}.brand span{font-size:14px}.nav-wrap nav{grid-template-columns:repeat(2,minmax(0,1fr))",
        "narrow phone navigation becomes one column": "@media(max-width:390px){.nav-wrap{grid-template-columns:1fr auto}.nav-wrap nav{grid-template-columns:1fr}",
        "content grids collapse to one column on phones": ".card-grid,.split,.state-grid{grid-template-columns:1fr}",
        "tablet state grid is readable": ".state-grid{grid-template-columns:repeat(2,minmax(0,1fr))}",
        "public anchors reserve only compact document-flow space": "html{scroll-behavior:smooth;scroll-padding-top:24px}",
        "responsive controls retain V1.1 target sizing": "glz11-button",
        "reduced transparency is explicitly handled": "@media(prefers-reduced-transparency:reduce)",
        "forced colors are explicitly handled": "@media(forced-colors:active)",
    }
    for label, marker in required.items():
        if marker not in css and marker != "glz11-button":
            errors.append(f"Missing responsive contract: {label}")

    html = (CSS.parent / "index.html").read_text(encoding="utf-8")
    if "glz11-button" not in html:
        errors.append("Missing responsive contract: responsive controls retain V1.1 target sizing")

    if ".site-header{position:sticky" in css or ".site-header{position:fixed" in css:
        errors.append("Security Center public navigation must remain in normal document flow")
    if "overflow-x:auto" in css and ".nav-wrap nav" in css:
        errors.append("Security Center primary navigation must not depend on horizontal scrolling")

    if errors:
        print("Security Center responsive validation failed:")
        for error in errors:
            print(f"  - {error}")
        return 1

    print("Security Center responsive layout validation passed: normal-flow header, 3/2/1-column navigation, phone content reflow, compact anchors, and accessibility fallbacks are protected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
