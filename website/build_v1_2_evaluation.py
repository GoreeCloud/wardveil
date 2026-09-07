#!/usr/bin/env python3
"""Build an isolated, non-production GLAZE UI V1.2 Stable Wardveil evaluation artifact."""
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "website"
DIST = SITE / "dist-v1.2-evaluation"
ICON = ROOT / "branding" / "wardveil-security-icon.svg"
BASE_CSS = "glaze-ui-v1.1.0.css"
EVAL_CSS = "glaze-ui-v1.2-frosted-neutral.evaluation.css"

if DIST.exists():
    shutil.rmtree(DIST)
(DIST / "assets").mkdir(parents=True)

html = (SITE / "index.html").read_text(encoding="utf-8")
html = html.replace(
    '<html lang="en" data-glaze-version="1.1" data-glaze-density-profile="standard" data-glaze-performance="balanced">',
    '<html lang="en" data-glaze-version="1.1" data-glaze-upgrade="v1.2-stable-evaluation" data-glaze-density-profile="standard" data-glaze-performance="balanced">',
    1,
)
html = html.replace(
    '<title>GoreeCloud Security Center — Wardveil Security</title>',
    '<title>GLAZE UI V1.2 Stable Evaluation — GoreeCloud Security Center</title>',
    1,
)
html = html.replace(
    '<meta name="goreecloud-glaze-ui" content="1.1.0">',
    '<meta name="goreecloud-glaze-ui" content="1.1.0">\n  <meta name="goreecloud-glaze-ui-evaluation" content="1.2.0-stable">\n  <meta name="goreecloud-evaluation" content="non-production">',
    1,
)
html = html.replace(
    f'<link rel="stylesheet" href="/assets/{BASE_CSS}" data-glaze-ui="1.1.0">',
    f'<link rel="stylesheet" href="/assets/{BASE_CSS}" data-glaze-ui="1.1.0">\n  <link rel="stylesheet" href="/assets/{EVAL_CSS}" data-glaze-ui-evaluation="1.2.0-stable">',
    1,
)
html = html.replace(
    '<header class="site-header" data-glaze-material-level="soft-glaze">',
    '<header class="site-header glz12-evaluation-glaze" data-glaze-material-level="soft-glaze">',
    1,
)
html = html.replace(
    '  <main id="main" class="shell" tabindex="-1">',
    '  <div class="glz12-evaluation-banner" role="note"><strong>Non-production GLAZE UI V1.2 Stable evaluation.</strong> This preview changes presentation only. Wardveil security state and production acceptance remain unchanged.</div>\n  <main id="main" class="shell" tabindex="-1">',
    1,
)
(DIST / "index.html").write_text(html, encoding="utf-8")

for name in ("_headers", "site.css", "site.js", BASE_CSS, EVAL_CSS):
    source = SITE / name
    target = DIST / name if name == "_headers" else DIST / "assets" / name
    shutil.copy2(source, target)
shutil.copy2(ICON, DIST / "assets" / "wardveil-security-icon.svg")

print(
    f"Built isolated {DIST.relative_to(ROOT)} V1.2 Stable evaluation artifact; "
    "production website/dist remains untouched"
)
