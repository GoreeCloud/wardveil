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
GLAZE_VERSION = "2.1.0"
GLAZE_REVISION = "c49113eb8b93c267613fdf1bbca1f814495acad7"
GLAZE_ASSET = f"glaze-ui-{GLAZE_VERSION}.css"

for name in ("index.html", "404.html", "site.css", "site.js", GLAZE_ASSET, "_headers", "build.py"):
    if not (SITE / name).is_file():
        raise SystemExit(f"missing website source: {name}")

subprocess.run([sys.executable, str(SITE / "build.py")], cwd=ROOT, check=True)

for name in ("index.html", "404.html", "_headers", "assets/site.css", "assets/site.js", f"assets/{GLAZE_ASSET}", "assets/wardveil-security-icon.svg"):
    if not (DIST / name).is_file():
        raise SystemExit(f"missing build artifact: {name}")

identity = json.loads(IDENTITY.read_text(encoding="utf-8"))
foundation_version = VERSION.read_text(encoding="utf-8").strip()
if not foundation_version:
    raise SystemExit("Wardveil VERSION file is empty")
if identity.get("foundation_version") != foundation_version:
    raise SystemExit("public site identity foundation version does not match VERSION")
visual = identity["visual_identity"]
if visual["canonical_visual_identity_status"] != "approved" or visual["showcase_status"] != "approved":
    raise SystemExit("Wardveil public visual showcase is not approved")
if visual.get("identity_name") != "Sentinel Fold":
    raise SystemExit("Wardveil public visual identity must be Sentinel Fold")

if ICON.read_bytes() != (DIST / "assets" / "wardveil-security-icon.svg").read_bytes():
    raise SystemExit("public Wardveil icon is not byte-identical to canonical identity source")

html = (DIST / "index.html").read_text(encoding="utf-8")
headers = (DIST / "_headers").read_text(encoding="utf-8")
glaze_css = (DIST / "assets" / GLAZE_ASSET).read_text(encoding="utf-8")
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
    "deployed ClamAV scanner path has production acceptance evidence",
    "End-to-end production acceptance remains evidence-gated",
    "Protected by Wardveil",
    "security@goreecloud.com",
    'name="goreecloud-glaze-ui" content="2.1.0"',
    'data-glaze-ui="2.1.0"',
):
    if needle not in html:
        raise SystemExit(f"required public content missing: {needle}")
for stale in ("Wardveil Security 0.7", "Foundation 0.7", "Read-only by default", "Glaze UI 1.5", "glaze-ui-1.5.0.css", "Glaze UI 2.0", "glaze-ui-2.0.0.css", "production runtime remains unaccepted"):
    if stale in html:
        raise SystemExit(f"stale Wardveil public content remains: {stale}")
for needle in ("Content-Security-Policy:", "frame-ancestors 'none'", "Permissions-Policy:", "X-Content-Type-Options: nosniff"):
    if needle not in headers:
        raise SystemExit(f"required security header missing: {needle}")
for prohibited in ("google-analytics", "googletagmanager", "segment.com", "fonts.googleapis.com"):
    if prohibited in html.lower():
        raise SystemExit(f"prohibited public dependency detected: {prohibited}")
for needle in (
    GLAZE_REVISION,
    "Content is solid. Interaction is glazed.",
    "--glaze-touch-min:48px",
    "--glaze-touch-assisted:56px",
    "data-glaze-density=compact",
    "data-glaze-performance=reduced",
    "data-glaze-large-text=true",
    "prefers-reduced-transparency",
    "forced-colors:active",
):
    if needle not in glaze_css:
        raise SystemExit(f"Glaze UI 2.1 Stable subset missing contract marker: {needle}")

print(f"Wardveil Security public website validation passed for foundation {foundation_version}, Sentinel Fold primary identity, and Glaze UI {GLAZE_VERSION} Stable")
