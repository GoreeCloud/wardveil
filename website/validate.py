#!/usr/bin/env python3
from pathlib import Path
import json
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "website"
DIST = SITE / "dist"
IDENTITY = ROOT / "contracts" / "wardveil.identity.json"
ICON = ROOT / "branding" / "wardveil-security-icon.svg"

for name in ("index.html", "404.html", "site.css", "site.js", "_headers", "build.py"):
    if not (SITE / name).is_file():
        raise SystemExit(f"missing website source: {name}")

subprocess.run([sys.executable, str(SITE / "build.py")], cwd=ROOT, check=True)

for name in ("index.html", "404.html", "_headers", "assets/site.css", "assets/site.js", "assets/wardveil-security-icon.svg"):
    if not (DIST / name).is_file():
        raise SystemExit(f"missing build artifact: {name}")

identity = json.loads(IDENTITY.read_text(encoding="utf-8"))
if identity["foundation_version"] != "0.6.0":
    raise SystemExit("public site foundation version must match current Wardveil identity contract")
visual = identity["visual_identity"]
if visual["canonical_visual_identity_status"] != "approved" or visual["showcase_status"] != "approved":
    raise SystemExit("Wardveil public visual showcase is not approved")

if ICON.read_bytes() != (DIST / "assets" / "wardveil-security-icon.svg").read_bytes():
    raise SystemExit("public Wardveil icon is not byte-identical to canonical identity source")

html = (DIST / "index.html").read_text(encoding="utf-8")
headers = (DIST / "_headers").read_text(encoding="utf-8")
for needle in ("Wardveil Security by GoreeCloud", "Security state without false reassurance", "Missing evidence fails closed", "Protected by Wardveil", "security@goreecloud.com"):
    if needle not in html:
        raise SystemExit(f"required public content missing: {needle}")
for needle in ("Content-Security-Policy:", "frame-ancestors 'none'", "Permissions-Policy:", "X-Content-Type-Options: nosniff"):
    if needle not in headers:
        raise SystemExit(f"required security header missing: {needle}")
for prohibited in ("google-analytics", "googletagmanager", "segment.com", "fonts.googleapis.com"):
    if prohibited in html.lower():
        raise SystemExit(f"prohibited public dependency detected: {prohibited}")

print("Wardveil Security public website validation passed")
