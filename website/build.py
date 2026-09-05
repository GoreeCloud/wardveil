#!/usr/bin/env python3
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "website"
DIST = SOURCE / "dist"
ICON = ROOT / "branding" / "wardveil-security-icon.svg"
GLAZE_ASSET = "glaze-ui-v1.1.0.css"

if DIST.exists():
    shutil.rmtree(DIST)
(DIST / "assets").mkdir(parents=True)

for name in ("index.html", "404.html", "_headers"):
    shutil.copy2(SOURCE / name, DIST / name)
for name in ("site.css", "site.js", GLAZE_ASSET):
    shutil.copy2(SOURCE / name, DIST / "assets" / name)
shutil.copy2(ICON, DIST / "assets" / "wardveil-security-icon.svg")
print(
    f"Built {DIST.relative_to(ROOT)} with canonical Wardveil identity "
    "and GLAZE UI V1.1 / 1.1.0 Stable adoption mapping"
)
