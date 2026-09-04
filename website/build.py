#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path
import shutil
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "website"
DIST = SOURCE / "dist"
ICON = ROOT / "branding" / "wardveil-security-icon.svg"
GLAZE_LOCK = SOURCE / "glaze.lock.json"


def git_blob_sha(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


lock = json.loads(GLAZE_LOCK.read_text(encoding="utf-8"))
if lock.get("version") != "1.1.0":
    raise SystemExit("Security Center Glaze lock must target 1.1.0 Stable")
if lock.get("entrypoint") != "css/glaze-v1.1.0.css":
    raise SystemExit("Security Center Glaze lock must use css/glaze-v1.1.0.css")
release_commit = lock.get("release_commit", "")
if len(release_commit) != 40:
    raise SystemExit("Security Center Glaze lock requires an immutable release commit")

if DIST.exists():
    shutil.rmtree(DIST)
(DIST / "assets" / "glaze").mkdir(parents=True)

for name in ("index.html", "404.html", "_headers"):
    shutil.copy2(SOURCE / name, DIST / name)
shutil.copy2(SOURCE / "site.js", DIST / "assets" / "site.js")
product_css = (SOURCE / "site.css").read_bytes() + b"\n" + (SOURCE / "desktop-fit.css").read_bytes()
(DIST / "assets" / "site.css").write_bytes(product_css)
shutil.copy2(ICON, DIST / "assets" / "wardveil-security-icon.svg")

for upstream_path, expected_blob in lock["files"].items():
    url = (
        "https://raw.githubusercontent.com/GoreeCloud/goreecloud-glaze-ui/"
        f"{release_commit}/{upstream_path}"
    )
    request = Request(url, headers={"User-Agent": "GoreeCloud-Security-Center-Build/1"})
    with urlopen(request, timeout=20) as response:
        data = response.read()
    actual_blob = git_blob_sha(data)
    if actual_blob != expected_blob:
        raise SystemExit(
            f"Glaze source identity mismatch for {upstream_path}: "
            f"expected {expected_blob}, got {actual_blob}"
        )
    (DIST / "assets" / "glaze" / Path(upstream_path).name).write_bytes(data)

print(
    f"Built {DIST.relative_to(ROOT)} with canonical Wardveil identity and "
    "immutable GLAZE UI V1.1 / 1.1.0 Stable web source"
)
