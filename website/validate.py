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
ADOPTION = SITE / "GLAZE-UI-2.1-ADOPTION.md"
WORKFLOW = ROOT / ".github" / "workflows" / "glaze-ui-2-validation.yml"
GLAZE_VERSION = "2.1.0"
GLAZE_REVISION = "c49113eb8b93c267613fdf1bbca1f814495acad7"
GLAZE_ASSET = f"glaze-ui-{GLAZE_VERSION}.css"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


for name in (
    "index.html",
    "404.html",
    "site.css",
    "site.js",
    GLAZE_ASSET,
    "_headers",
    "build.py",
    "GLAZE-UI-2.1-ADOPTION.md",
):
    require((SITE / name).is_file(), f"missing website source: {name}")
require(WORKFLOW.is_file(), "missing Security Center Glaze UI validation workflow")
require(not (SITE / "glaze-ui-2.0.0.css").exists(), "superseded Glaze UI 2.0 asset must not remain in active website source")

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
    'name="goreecloud-glaze-ui" content="2.1.0"',
    'data-glaze-ui="2.1.0"',
    'data-glaze-density="standard"',
    'data-glaze-performance="balanced"',
    "Glaze UI 2.1",
    "Stable 2.1 is the current site baseline",
):
    require(needle in html, f"required public content missing: {needle}")

for document in (html, not_found):
    for stale in (
        "Glaze UI 2.0",
        "Stable 2.0",
        'content="2.0.0"',
        'data-glaze-ui="2.0.0"',
        "glaze-ui-2.0.0.css",
    ):
        require(stale not in document, f"stale Glaze UI 2.0 public content remains: {stale}")

require(
    html.index('/assets/glaze-ui-2.1.0.css') < html.index('/assets/site.css'),
    "Glaze UI Stable subset must load before Wardveil product styling",
)
require(
    not_found.index('/assets/glaze-ui-2.1.0.css') < not_found.index('/assets/site.css'),
    "404 page must load Glaze UI Stable subset before Wardveil product styling",
)
require(
    html.count('data-glaze-material-level="soft-glaze"') == 1,
    "Security Center administration recipe must keep Soft Glaze bounded to one persistent chrome surface",
)
require(
    html.count('data-glaze-material-level="surface"') >= 8,
    "Security Center content must explicitly map primary content planes to solid Surface",
)
for forbidden_level in ('data-glaze-material-level="deep-glaze"', 'data-glaze-material-level="live-glaze"'):
    require(forbidden_level not in html, f"Security Center site exceeds bounded administration material mapping: {forbidden_level}")

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
    GLAZE_REVISION,
    "--glaze-touch-min:48px",
    "--glaze-touch-assistance-min:56px",
    "data-glaze-material-level=surface",
    "data-glaze-material-level=soft-glaze",
    "prefers-reduced-transparency",
    "prefers-reduced-motion",
    "prefers-contrast:more",
    "forced-colors:active",
    "data-glaze-performance=constrained",
    "data-glaze-performance=minimal",
    "@supports not ((backdrop-filter:blur(1px))",
):
    require(needle in glaze_css, f"Glaze UI 2.1 Stable subset missing contract marker: {needle}")
require(
    ".glass-card{background:var(--surface-strong);" in site_css,
    "Wardveil content cards must remain solid product surfaces under Glaze UI 2.1",
)
require(
    "dataset.glazeAppearance" in site_js and "removeAttribute('data-glaze-appearance')" in site_js,
    "Wardveil appearance control must map to Glaze UI appearance state",
)

for needle in (
    "Status: **Adoption Candidate**",
    "Target: **Glaze UI 2.1.0 Stable**",
    GLAZE_REVISION,
    "administration",
    "48 px floor",
    "56 px floor",
    "Reduced Transparency",
    "Forced Colors",
    "human Visual Excellence approval",
    "does **not** by itself establish final product acceptance",
    "Wardveil Security remains the authority for security truth",
):
    require(needle in adoption, f"Glaze UI 2.1 adoption record missing boundary: {needle}")

for needle in (
    "Validate Security Center Glaze UI 2.1 Stable",
    "persist-credentials: false",
    "Verify exact source revision",
    "python3 website/validate.py",
):
    require(needle in workflow, f"Security Center Glaze UI workflow missing invariant: {needle}")

print(
    "Wardveil Security public website validation passed for "
    f"foundation {foundation_version}, Sentinel Fold primary identity, and "
    f"Glaze UI {GLAZE_VERSION} Stable source-level Adoption Candidate mapping"
)
