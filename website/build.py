#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path
import re
import shutil
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "website"
DIST = SOURCE / "dist"
ICON = ROOT / "branding" / "wardveil-security-icon.svg"
GLAZE_LOCK = SOURCE / "glaze.lock.json"
EXPECTED_RELEASE = "15cc76d2bcd4065552dc31c77145b63f34d9e7b2"
IMPORT_DIRECTIVE_RE = re.compile(r"@import\s+[^;]+;", re.IGNORECASE)
IMPORT_TARGET_RE = re.compile(
    r"@import\s+(?:url\(\s*)?[\"'](?P<target>[^\"']+)[\"']\s*\)?\s*;",
    re.IGNORECASE,
)


def git_blob_sha(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def require_glaze_name(name: str) -> str:
    if (
        not name.endswith(".css")
        or "/" in name
        or "\\" in name
        or name in {".", ".."}
    ):
        raise SystemExit(f"unsafe Glaze asset name: {name}")
    return name


def load_lock() -> dict[str, object]:
    lock = json.loads(GLAZE_LOCK.read_text(encoding="utf-8"))
    if lock.get("version") != "1.1.0":
        raise SystemExit("Security Center Glaze lock must target 1.1.0 Stable")
    if lock.get("entrypoint") != "css/glaze-v1.1.0.css":
        raise SystemExit("Security Center Glaze lock must use css/glaze-v1.1.0.css")
    if lock.get("release_commit") != EXPECTED_RELEASE:
        raise SystemExit("Security Center Glaze lock requires the governed immutable release commit")
    if lock.get("runtime_network_dependency_required") is not False:
        raise SystemExit("Security Center browser runtime must not depend on a remote Glaze source")
    files = lock.get("files")
    if not isinstance(files, dict) or len(files) != 13:
        raise SystemExit("Security Center Glaze lock must contain the 13 expected CSS files")
    return lock


def fetch_verified_glaze_assets() -> dict[str, bytes]:
    lock = load_lock()
    files = lock["files"]
    assert isinstance(files, dict)
    release_commit = str(lock["release_commit"])
    assets: dict[str, bytes] = {}

    for upstream_path, expected_blob in files.items():
        if not isinstance(upstream_path, str) or not isinstance(expected_blob, str):
            raise SystemExit("invalid Security Center Glaze lock entry")
        name = require_glaze_name(Path(upstream_path).name)
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
        assets[name] = data

    validate_glaze_import_closure(assets)
    return assets


def validate_glaze_import_closure(assets: dict[str, bytes]) -> None:
    """Require every local CSS import to resolve inside the locked graph."""

    for name, data in assets.items():
        try:
            css = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SystemExit(f"Glaze stylesheet is not UTF-8: {name}") from exc

        directives = IMPORT_DIRECTIVE_RE.findall(css)
        targets = [match.group("target") for match in IMPORT_TARGET_RE.finditer(css)]
        if len(directives) != len(targets):
            raise SystemExit(f"unsupported or ambiguous CSS @import syntax in {name}")

        for target in targets:
            if not target.startswith("./"):
                raise SystemExit(f"Glaze import must be same-directory relative in {name}: {target}")
            if any(marker in target for marker in ("?", "#", "..")):
                raise SystemExit(f"unsafe Glaze import target in {name}: {target}")
            imported_name = require_glaze_name(target[2:])
            if imported_name not in assets:
                raise SystemExit(
                    f"Glaze import closure failure: {name} imports missing {imported_name}"
                )


def build() -> None:
    # Fetch, byte-verify, and validate the complete immutable dependency graph
    # before touching generated publication output. A byte-perfect but
    # dependency-incomplete release must not erase or replace existing dist.
    glaze_assets = fetch_verified_glaze_assets()

    if DIST.exists():
        if DIST.is_symlink():
            raise SystemExit("unsafe Security Center dist symlink")
        shutil.rmtree(DIST)
    (DIST / "assets" / "glaze").mkdir(parents=True)

    for name in ("index.html", "404.html", "_headers"):
        shutil.copy2(SOURCE / name, DIST / name)
    shutil.copy2(SOURCE / "site.js", DIST / "assets" / "site.js")
    product_css = (SOURCE / "site.css").read_bytes() + b"\n" + (SOURCE / "desktop-fit.css").read_bytes()
    (DIST / "assets" / "site.css").write_bytes(product_css)
    shutil.copy2(ICON, DIST / "assets" / "wardveil-security-icon.svg")

    for name, data in glaze_assets.items():
        (DIST / "assets" / "glaze" / name).write_bytes(data)

    print(
        f"Built {DIST.relative_to(ROOT)} with canonical Wardveil identity and "
        "a complete immutable GLAZE UI V1.1 / 1.1.0 source graph"
    )


if __name__ == "__main__":
    build()
