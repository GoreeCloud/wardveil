#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "website"
DIST = SITE / "dist"
IDENTITY = ROOT / "contracts" / "wardveil.identity.json"
VERSION = ROOT / "VERSION"
ICON = ROOT / "branding" / "wardveil-security-icon.svg"
LOCK = SITE / "glaze.lock.json"
WORKFLOW = ROOT / ".github" / "workflows" / "glaze-ui-v1.1-validation.yml"
EXPECTED_RELEASE = "15cc76d2bcd4065552dc31c77145b63f34d9e7b2"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


for name in ("index.html", "404.html", "site.css", "site.js", "_headers", "build.py", "glaze.lock.json"):
    require((SITE / name).is_file(), f"missing website source: {name}")
require(WORKFLOW.is_file(), "missing Security Center Glaze UI V1.1 validation workflow")
for stale_path in ("glaze-ui-1.5.0.css", "glaze-ui-2.0.0.css", "glaze-ui-2.1.0.css"):
    require(not (SITE / stale_path).exists(), f"superseded active Glaze asset remains: {stale_path}")

lock = json.loads(LOCK.read_text(encoding="utf-8"))
require(lock.get("version") == "1.1.0", "Glaze lock must target 1.1.0")
require(lock.get("release_commit") == EXPECTED_RELEASE, "Glaze lock release commit drifted")
require(lock.get("entrypoint") == "css/glaze-v1.1.0.css", "Glaze lock entrypoint drifted")
require(lock.get("runtime_network_dependency_required") is False, "runtime Glaze network dependency must remain false")
require(len(lock.get("files", {})) == 13, "Glaze V1.1 Stable web graph must contain 13 locked files")

subprocess.run([sys.executable, str(SITE / "build.py")], cwd=ROOT, check=True)

for name in ("index.html", "404.html", "_headers", "assets/site.css", "assets/site.js", "assets/wardveil-security-icon.svg", "assets/glaze/glaze-v1.1.0.css"):
    require((DIST / name).is_file(), f"missing build artifact: {name}")
require(ICON.read_bytes() == (DIST / "assets" / "wardveil-security-icon.svg").read_bytes(), "published Wardveil icon is not canonical")
for upstream_path, expected_blob in lock["files"].items():
    built = DIST / "assets" / "glaze" / Path(upstream_path).name
    require(built.is_file(), f"missing locked Glaze artifact: {upstream_path}")
    require(git_blob_sha(built.read_bytes()) == expected_blob, f"Glaze blob identity drifted: {upstream_path}")

identity = json.loads(IDENTITY.read_text(encoding="utf-8"))
foundation_version = VERSION.read_text(encoding="utf-8").strip()
require(identity.get("foundation_version") == foundation_version, "website foundation version does not match Wardveil identity")
visual = identity["visual_identity"]
require(visual.get("canonical_visual_identity_status") == "approved", "Wardveil identity is not approved")
require(visual.get("showcase_status") == "approved", "Wardveil identity is not showcase-approved")
require(visual.get("identity_name") == "Sentinel Fold", "Wardveil identity must be Sentinel Fold")

html = (DIST / "index.html").read_text(encoding="utf-8")
not_found = (DIST / "404.html").read_text(encoding="utf-8")
site_css = (DIST / "assets" / "site.css").read_text(encoding="utf-8")
site_js = (DIST / "assets" / "site.js").read_text(encoding="utf-8")
headers = (DIST / "_headers").read_text(encoding="utf-8")
glaze_css = "\n".join((DIST / "assets" / "glaze" / Path(path).name).read_text(encoding="utf-8") for path in lock["files"])

for needle in (
    'data-glaze-version="1.1"',
    'name="goreecloud-glaze-ui" content="1.1.0"',
    '/assets/glaze/glaze-v1.1.0.css',
    "Wardveil Security by GoreeCloud",
    "Wardveil Security 0.9",
    "Sentinel Fold is the primary Wardveil mark",
    "ClamAV is an engine beneath Wardveil Scan",
    "Missing evidence",
    "security@goreecloud.com",
    "GLAZE UI V1.1 / 1.1.0 Stable",
):
    require(needle in html, f"required public content missing: {needle}")
for document in (html, not_found):
    for stale in ("Glaze UI 1.5", "Glaze UI 2.0", "Glaze UI 2.1", "Glaze UI 2.2", "glaze-ui-2.1.0.css", 'data-glaze-material-level=', 'class="glass-card'):
        require(stale not in document, f"superseded public presentation remains: {stale}")
require(html.count("glz11-soft-glaze") == 1, "Soft Glaze must remain bounded to persistent navigation chrome")
require(html.count("solid-card") >= 8, "durable Security Center content must use solid surfaces")
require(html.index('/assets/glaze/glaze-v1.1.0.css') < html.index('/assets/site.css'), "Glaze V1.1 must load before product styling")
require(not_found.index('/assets/glaze/glaze-v1.1.0.css') < not_found.index('/assets/site.css'), "404 must load Glaze V1.1 before product styling")

ids = set(re.findall(r'\bid="([^"]+)"', html))
for anchor in re.findall(r'href="#([^"]+)"', html):
    require(anchor in ids, f"broken same-page anchor: #{anchor}")
for local_asset in re.findall(r'(?:href|src)="(/assets/[^"]+)"', html + not_found):
    require((DIST / local_asset.lstrip("/")).is_file(), f"missing referenced asset: {local_asset}")

for needle in ("Content-Security-Policy:", "frame-ancestors 'none'", "Permissions-Policy:", "X-Content-Type-Options: nosniff"):
    require(needle in headers, f"required security header missing: {needle}")
for prohibited in ("google-analytics", "googletagmanager", "segment.com", "fonts.googleapis.com", "fonts.gstatic.com"):
    require(prohibited not in html.lower(), f"prohibited public dependency detected: {prohibited}")

for needle in ("--glz11-target-min: 48px", "data-glz-touch-assistance=\"true\"", "--glz11-target-min: 56px", "prefers-reduced-motion", "prefers-reduced-transparency", "prefers-contrast: more", "forced-colors: active"):
    require(needle in glaze_css, f"canonical Glaze V1.1 accessibility contract missing: {needle}")
for needle in ("@media(max-width:960px)", "@media(max-width:640px)", "@media(max-width:390px)", "prefers-reduced-motion:reduce", "prefers-reduced-transparency:reduce", "prefers-contrast:more", "forced-colors:active", "min-height:48px"):
    require(needle in site_css, f"Security Center responsive/accessibility rule missing: {needle}")
require("data-glz-appearance" in site_js and "deep-dark" in site_js, "appearance control must use V1.1 appearance contract")

workflow = WORKFLOW.read_text(encoding="utf-8")
for needle in ("Validate Security Center GLAZE UI V1.1 Stable", "persist-credentials: false", "Verify exact source revision", "python3 website/validate.py", "browser_responsive_smoke.py"):
    require(needle in workflow, f"website workflow missing invariant: {needle}")

print(f"Wardveil Security Center source validation passed for Foundation {foundation_version} and GLAZE UI V1.1 / 1.1.0 Stable source graph")
