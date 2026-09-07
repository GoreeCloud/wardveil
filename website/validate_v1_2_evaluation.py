#!/usr/bin/env python3
"""Validate the isolated Wardveil GLAZE UI V1.2 Stable Frosted Neutral evaluation."""
from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "website"
PROD = SITE / "dist"
EVAL = SITE / "dist-v1.2-evaluation"
SOURCE_HTML = SITE / "index.html"
EVAL_CSS_PATH = SITE / "glaze-ui-v1.2-frosted-neutral.evaluation.css"
RECORD = SITE / "GLAZE-UI-V1.2-EVALUATION.md"
BROWSER_SMOKE = SITE / "browser_v1_2_evaluation_smoke.py"
WORKFLOW = ROOT / ".github" / "workflows" / "glaze-ui-v1.2-evaluation.yml"
STABLE_RELEASE_SHA = "f285b9145e27e6e7027b075c37299d101945c272"
SOURCE_QUALIFICATION_ANCHOR = "b0eadf9a60f73d45caffb62ffc7e9e0334cddc97"
UPLOAD_ARTIFACT_SHA = "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"


def require(ok: bool, message: str) -> None:
    if not ok:
        raise SystemExit(f"Wardveil V1.2 evaluation validation failed: {message}")


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def main() -> int:
    for path in (
        SOURCE_HTML,
        EVAL_CSS_PATH,
        RECORD,
        BROWSER_SMOKE,
        WORKFLOW,
        SITE / "build.py",
        SITE / "build_v1_2_evaluation.py",
    ):
        require(path.is_file(), f"missing required source: {path.relative_to(ROOT)}")

    source_html = SOURCE_HTML.read_text(encoding="utf-8")
    require('data-glaze-version="1.1"' in source_html, "production source must remain on V1.1")
    require('data-glaze-upgrade="v1.2-stable-evaluation"' not in source_html, "production source must not opt into V1.2 Stable evaluation")
    require('glaze-ui-v1.2-frosted-neutral.evaluation.css' not in source_html, "production source must not load evaluation CSS")
    require('goreecloud-glaze-ui-evaluation' not in source_html, "production source must not publish evaluation metadata")
    require('goreecloud-glaze-ui-candidate' not in source_html, "production source must not publish stale Candidate metadata")

    subprocess.run([sys.executable, str(SITE / "build.py")], cwd=ROOT, check=True)
    require(PROD.is_dir(), "production build missing after build.py")
    production_before = tree_digest(PROD)
    prod_html = (PROD / "index.html").read_text(encoding="utf-8")
    require('data-glaze-upgrade="v1.2-stable-evaluation"' not in prod_html, "production artifact opted into V1.2 Stable evaluation")
    require(not (PROD / "assets" / EVAL_CSS_PATH.name).exists(), "production artifact ships V1.2 evaluation CSS")

    subprocess.run([sys.executable, str(SITE / "build_v1_2_evaluation.py")], cwd=ROOT, check=True)
    require(EVAL.is_dir(), "evaluation build missing")
    production_after = tree_digest(PROD)
    require(production_before == production_after, "evaluation builder mutated production website/dist")

    for path in (
        EVAL / "index.html",
        EVAL / "_headers",
        EVAL / "assets" / "site.css",
        EVAL / "assets" / "site.js",
        EVAL / "assets" / "glaze-ui-v1.1.0.css",
        EVAL / "assets" / EVAL_CSS_PATH.name,
        EVAL / "assets" / "wardveil-security-icon.svg",
    ):
        require(path.is_file(), f"evaluation artifact missing: {path.relative_to(EVAL)}")

    html = (EVAL / "index.html").read_text(encoding="utf-8")
    css = (EVAL / "assets" / EVAL_CSS_PATH.name).read_text(encoding="utf-8")
    record = RECORD.read_text(encoding="utf-8")
    browser_smoke = BROWSER_SMOKE.read_text(encoding="utf-8")
    workflow = WORKFLOW.read_text(encoding="utf-8")

    for needle in (
        'data-glaze-version="1.1"',
        'data-glaze-upgrade="v1.2-stable-evaluation"',
        'name="goreecloud-glaze-ui" content="1.1.0"',
        'name="goreecloud-glaze-ui-evaluation" content="1.2.0-stable"',
        'name="goreecloud-evaluation" content="non-production"',
        'data-glaze-ui-evaluation="1.2.0-stable"',
        'class="site-header glz12-evaluation-glaze"',
        'Non-production GLAZE UI V1.2 Stable evaluation.',
    ):
        require(needle in html, f"evaluation artifact missing marker: {needle}")

    require('goreecloud-glaze-ui-candidate' not in html, "evaluation artifact must not describe V1.2 Stable as Candidate")
    require('1.2.0-candidate' not in html, "evaluation artifact contains stale V1.2 Candidate lifecycle metadata")
    require(html.count("glz12-evaluation-glaze") == 1, "evaluation must use exactly one Frosted Neutral region")
    require(html.count('data-glaze-material-level="surface"') >= 8, "Security Center reading surfaces must remain explicit solid Surface")
    require('data-glaze-material-level="deep-glaze"' not in html, "evaluation must not introduce Deep Glaze")
    require('data-glaze-material-level="live-glaze"' not in html, "evaluation must not introduce Live Glaze")
    require(
        html.index('/assets/glaze-ui-v1.1.0.css')
        < html.index('/assets/glaze-ui-v1.2-frosted-neutral.evaluation.css')
        < html.index('/assets/site.css'),
        "evaluation layer must load after accepted production base and before Wardveil product styling",
    )

    for needle in (
        STABLE_RELEASE_SHA,
        SOURCE_QUALIFICATION_ANCHOR,
        "Neutral glass is the material. Color is an accent.",
        "--glz12-glass-overlay:rgba(250,250,250,.82)",
        "--glz12-glass-overlay:rgba(42,42,45,.82)",
        "--glz12-glass-overlay:rgba(24,24,27,.86)",
        "--glz12-blur-standard:28px",
        'data-glz-transparency="reduced"',
        "@media(max-width:620px)",
        ".glz12-evaluation-glaze .nav-wrap nav",
        "overflow-x:auto",
        "overscroll-behavior-inline:contain",
        "min-width:48px",
        "white-space:nowrap",
        "prefers-reduced-transparency:reduce",
        "prefers-contrast:more",
        "forced-colors:active",
        "@supports not ((backdrop-filter:blur(1px))",
        ".glass-card,",
        'data-glaze-material-level="surface"',
    ):
        require(needle in css, f"evaluation CSS missing Stable contract marker: {needle}")

    for forbidden in (
        "rgba(15,107,111",
        "rgba(217,163,95",
        "--glz11-tint-glaze-teal",
        "--glz11-tint-glaze-amber",
    ):
        require(forbidden not in css, f"evaluation substrate reintroduced V1.1 chromatic material tint: {forbidden}")

    for needle in (
        "Status: **Non-production evaluation**",
        "Active production target: **GLAZE UI V1.1 / 1.1.0 Stable**",
        "Design-system release evaluated: **GLAZE UI V1.2 / 1.2.0 Stable**",
        STABLE_RELEASE_SHA,
        SOURCE_QUALIFICATION_ANCHOR,
        "persistent site header is the **only** Frosted Neutral region",
        "human optical approval",
        "production Cloudflare Pages acceptance",
        "must therefore never describe V1.2 itself as Candidate or RC",
        "Rollback is immediate",
        "five deterministic review screenshots",
    ):
        require(needle in record, f"evaluation record missing boundary: {needle}")

    for forbidden in (
        "Candidate evaluated: **GLAZE UI V1.2 / 1.2.0-candidate**",
        "GLAZE UI V1.2 Release Candidate or Stable status",
    ):
        require(forbidden not in record, f"evaluation record contains stale lifecycle claim: {forbidden}")

    for needle in (
        STABLE_RELEASE_SHA,
        SOURCE_QUALIFICATION_ANCHOR,
        "WARDVEIL_V12_SCREENSHOT_DIR",
        "WARDVEIL_EVIDENCE_SHA",
        '"wardveil_source_revision": evidence_sha',
        '"upstream_glaze_stable_revision": UPSTREAM_GLAZE_STABLE_SHA',
        '"upstream_glaze_source_qualification_anchor": UPSTREAM_GLAZE_SOURCE_ANCHOR',
        "mobile evaluation header consumes excessive viewport height",
        "mobile Stable evaluation navigation must be a compact flex capsule",
        "mobile Stable evaluation navigation must scroll horizontally",
        "Deep Dark did not activate Wardveil product dark theme",
        "dark capture contains a light Security Center surface",
        '"product_theme": state.get("productTheme")',
        '"appearance_label": state.get("label")',
        '"surface_background": state.get("surfaceBackground")',
        'capture("01-light-desktop", 1180, 900, "light")',
        'capture("02-light-mobile", 390, 844, "light")',
        'capture("03-dark-desktop", 1180, 900, "dark")',
        'capture("04-deep-dark-desktop", 1180, 900, "deep-dark")',
        'capture("05-reduced-transparency-desktop", 1180, 900, "light", True)',
        '"non_production": True',
        '"capture_count": len(captures)',
        "Automated screenshots are review evidence only",
    ):
        require(needle in browser_smoke, f"browser optical-evidence harness missing invariant: {needle}")

    for forbidden in (
        "UPSTREAM_GLAZE_SHA",
        "upstream_glaze_candidate_revision",
        "goreecloud-glaze-ui-candidate",
        "1.2.0-candidate",
    ):
        require(forbidden not in browser_smoke, f"browser harness contains stale Candidate lifecycle marker: {forbidden}")

    for needle in (
        "Revalidate active V1.1 production source",
        "Validate isolated V1.2 Stable evaluation contract",
        "Exercise V1.2 Stable evaluation in Chrome and capture review evidence",
        "WARDVEIL_V12_SCREENSHOT_DIR: website/evidence/v1.2-evaluation",
        "WARDVEIL_EVIDENCE_SHA: ${{ github.event_name == 'pull_request' && github.event.pull_request.head.sha || github.sha }}",
        f"actions/upload-artifact@{UPLOAD_ARTIFACT_SHA}",
        "name: wardveil-v1.2-frosted-neutral-optical-review",
        "if-no-files-found: error",
        "retention-days: 14",
    ):
        require(needle in workflow, f"evaluation workflow missing evidence-pipeline invariant: {needle}")

    require("V1.2 Candidate" not in workflow, "evaluation workflow still describes V1.2 as Candidate")

    print(
        "Wardveil Security Center GLAZE UI V1.2 Stable evaluation: PASS — "
        "isolated artifact, one Frosted Neutral header region, solid security-reading surfaces, "
        "compact mobile navigation, synchronized Wardveil/Glaze appearance evidence, "
        "governed exact-head optical-review evidence pipeline, "
        f"upstream Stable {STABLE_RELEASE_SHA}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
