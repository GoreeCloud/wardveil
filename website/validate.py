#!/usr/bin/env python3
from pathlib import Path
import json
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "website"
DIST = SITE / "dist"
IDENTITY = ROOT / "contracts" / "wardveil.identity.json"
VERSION = ROOT / "VERSION"
ICON = ROOT / "branding" / "wardveil-security-icon.svg"
ADOPTION = SITE / "GLAZE-UI-V1.6-ADOPTION.md"
HISTORICAL_V11_ADOPTION = SITE / "GLAZE-UI-V1.1-ADOPTION.md"
HISTORICAL_V21_ADOPTION = SITE / "GLAZE-UI-2.1-ADOPTION.md"
WORKFLOW = ROOT / ".github" / "workflows" / "glaze-ui-v1-validation.yml"
GLAZE_VERSION = "1.6.0"
GLAZE_PRODUCT = "GLAZE UI V1.6"
GLAZE_RELEASE_SOURCE = "a7180679ea851389e0f3004515f9a25f420e716d"
GLAZE_ASSET = "glaze-ui-v1.6.0.css"
HISTORICAL_ASSETS = ("glaze-ui-v1.1.0.css", "glaze-ui-2.1.0.css")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


for name in (
    "index.html",
    "404.html",
    "site.css",
    "site.js",
    GLAZE_ASSET,
    *HISTORICAL_ASSETS,
    "_headers",
    "build.py",
    "GLAZE-UI-V1.6-ADOPTION.md",
    "GLAZE-UI-V1.1-ADOPTION.md",
    "GLAZE-UI-2.1-ADOPTION.md",
):
    require((SITE / name).is_file(), f"missing website source or retained history: {name}")
require(WORKFLOW.is_file(), "missing Security Center GLAZE UI validation workflow")
require(HISTORICAL_V11_ADOPTION.is_file(), "historical GLAZE UI V1.1 adoption evidence must remain retained")
require(HISTORICAL_V21_ADOPTION.is_file(), "historical Glaze UI 2.1 adoption evidence must remain retained")

subprocess.run([sys.executable, str(SITE / "build.py")], cwd=ROOT, check=True)

for name in (
    "index.html",
    "404.html",
    "_headers",
    "assets/site.css",
    "assets/site.js",
    f"assets/{GLAZE_ASSET}",
    "assets/wardveil-security-icon.svg",
):
    require((DIST / name).is_file(), f"missing build artifact: {name}")
for historical in HISTORICAL_ASSETS:
    require(not (DIST / "assets" / historical).exists(), f"historical Glaze asset must not ship: {historical}")

identity = json.loads(IDENTITY.read_text(encoding="utf-8"))
foundation_version = VERSION.read_text(encoding="utf-8").strip()
require(bool(foundation_version), "Wardveil VERSION file is empty")
require(identity.get("foundation_version") == foundation_version, "public site identity foundation version does not match VERSION")
visual = identity["visual_identity"]
require(
    visual["canonical_visual_identity_status"] == "approved"
    and visual["showcase_status"] == "approved",
    "Wardveil public visual showcase is not approved",
)
require(visual.get("identity_name") == "Sentinel Fold", "Wardveil public visual identity must be Sentinel Fold")

require(
    ICON.read_bytes() == (DIST / "assets" / "wardveil-security-icon.svg").read_bytes(),
    "public Wardveil icon is not byte-identical to canonical identity source",
)
for source, built in (
    (SITE / GLAZE_ASSET, DIST / "assets" / GLAZE_ASSET),
    (SITE / "site.css", DIST / "assets" / "site.css"),
    (SITE / "site.js", DIST / "assets" / "site.js"),
):
    require(source.read_bytes() == built.read_bytes(), f"build artifact drifted from source: {source.name}")

html = (DIST / "index.html").read_text(encoding="utf-8")
not_found = (DIST / "404.html").read_text(encoding="utf-8")
headers = (DIST / "_headers").read_text(encoding="utf-8")
glaze_css = (DIST / "assets" / GLAZE_ASSET).read_text(encoding="utf-8")
site_css = (DIST / "assets" / "site.css").read_text(encoding="utf-8")
site_js = (DIST / "assets" / "site.js").read_text(encoding="utf-8")
adoption = ADOPTION.read_text(encoding="utf-8")
historical_v11 = HISTORICAL_V11_ADOPTION.read_text(encoding="utf-8")
historical_v21 = HISTORICAL_V21_ADOPTION.read_text(encoding="utf-8")
workflow = WORKFLOW.read_text(encoding="utf-8")
major_minor = ".".join(foundation_version.split(".")[:2])

for needle in (
    "Wardveil Security by GoreeCloud",
    f"Wardveil Security {major_minor}",
    f"Foundation {major_minor}",
    "Sentinel Fold is the primary Wardveil mark",
    "standalone Sentinel Fold emblem is the owner-approved primary visual mark",
    "Missing evidence fails closed",
    "Wardveil Protect",
    "runtime authorization",
    "ClamAV is an engine beneath Wardveil Scan",
    "production runtime remains unaccepted",
    "Protected by Wardveil",
    "security@goreecloud.com",
    'name="goreecloud-glaze-ui" content="1.6.0"',
    'data-glaze-ui="1.6.0"',
    'data-glaze-version="1.6"',
    'data-glaze-density="standard"',
    'data-glaze-performance="balanced"',
    "GLAZE UI V1.6 source",
    "current shared Stable GLAZE UI V1.6 / 1.6.0 presentation contract",
    "source/build migration does not establish rendered",
):
    require(needle in html, f"required public content missing: {needle}")

for document in (html, not_found):
    for stale in (
        'content="1.1.0"',
        'data-glaze-ui="1.1.0"',
        'data-glaze-version="1.1"',
        "glaze-ui-v1.1.0.css",
        'content="2.1.0"',
        'data-glaze-ui="2.1.0"',
        "glaze-ui-2.1.0.css",
    ):
        require(stale not in document, f"historical Glaze UI target remains active: {stale}")

require(
    html.index(f'/assets/{GLAZE_ASSET}') < html.index('/assets/site.css'),
    "GLAZE UI V1.6 subset must load before Wardveil product styling",
)
require(
    not_found.index(f'/assets/{GLAZE_ASSET}') < not_found.index('/assets/site.css'),
    "404 page must load GLAZE UI V1.6 subset before Wardveil product styling",
)
require(
    html.count('data-glaze-material-level="soft-glaze"') == 1,
    "Security Center must keep Soft Glaze bounded to one persistent chrome surface",
)
require(
    html.count('data-glaze-material-level="surface"') >= 8,
    "Security Center content must explicitly map primary content planes to solid Surface",
)
for forbidden_level in ('data-glaze-material-level="deep-glaze"', 'data-glaze-material-level="live-glaze"'):
    require(forbidden_level not in html, f"Security Center exceeds bounded material mapping: {forbidden_level}")

for needle in (
    "Content-Security-Policy:",
    "frame-ancestors 'none'",
    "Permissions-Policy:",
    "X-Content-Type-Options: nosniff",
):
    require(needle in headers, f"required security header missing: {needle}")
for prohibited in ("google-analytics", "googletagmanager", "segment.com", "fonts.googleapis.com"):
    require(prohibited not in html.lower(), f"prohibited public dependency detected: {prohibited}")

for needle in (
    GLAZE_RELEASE_SOURCE,
    'html[data-glaze-version="1.6"]',
    "--glaze-touch-min:48px",
    "--glaze-touch-assistance-min:56px",
    'data-glz-touch-assistance="true"',
    "prefers-reduced-transparency",
    "prefers-reduced-motion",
    "prefers-contrast:more",
    "forced-colors:active",
    'data-glaze-performance="constrained"',
    'data-glaze-performance="minimal"',
    "@supports not ((backdrop-filter:blur(1px))",
):
    require(needle in glaze_css, f"GLAZE UI V1.6 source subset missing contract marker: {needle}")
require(
    ".glass-card{background:var(--surface-strong);" in site_css,
    "Wardveil content cards must remain solid product surfaces under GLAZE UI V1.6",
)
require(
    "dataset.glzAppearance" in site_js and "removeAttribute('data-glz-appearance')" in site_js,
    "Wardveil appearance control must retain explicit local appearance mapping",
)

for needle in (
    "Status: **Source Adoption Candidate / consumer acceptance pending**",
    "Target: **GLAZE UI V1.6 / 1.6.0 Stable**",
    GLAZE_RELEASE_SOURCE,
    "Known-good rollback baseline: **1.5.1**",
    "48 px floor",
    "56 px floor",
    "Reduced Transparency",
    "Forced Colors",
    "source/build migration evidence only",
    "canonical Glaze consumer registry currently requires V1.6.0",
    "Wardveil Security remains the authority for security truth",
):
    require(needle in adoption, f"GLAZE UI V1.6 adoption record missing boundary: {needle}")
require("GLAZE UI V1.1 Adoption" in historical_v11, "retained V1.1 adoption record must remain identifiable")
require("Glaze UI 2.1 Adoption" in historical_v21, "retained 2.1 adoption record must remain identifiable")

for needle in (
    "Validate Security Center GLAZE UI V1.6 source adoption",
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
    "persist-credentials: false",
    "Verify exact source revision",
    "python3 website/validate.py",
    "python3 website/validate_responsive.py",
    "python3 website/browser_responsive_smoke.py",
):
    require(needle in workflow, f"Security Center GLAZE UI workflow missing invariant: {needle}")

print(
    "Wardveil Security public website validation passed for "
    f"foundation {foundation_version}, Sentinel Fold primary identity, and "
    f"{GLAZE_PRODUCT} / {GLAZE_VERSION} source/build Adoption Candidate mapping; "
    "rendered/deployment/production consumer acceptance remains pending"
)
