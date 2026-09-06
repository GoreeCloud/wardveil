#!/usr/bin/env python3
"""Exercise Wardveil's isolated V1.2 evaluation in headless Chrome and optionally capture review evidence."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from typing import Any
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
SITE = ROOT / "dist-v1.2-evaluation"
WEB_PORT = 8766
DRIVER_PORT = 9519
BASE = f"http://127.0.0.1:{DRIVER_PORT}"
TARGET = f"http://127.0.0.1:{WEB_PORT}/"
VIEWPORTS = ((1180, 900), (768, 900), (390, 844), (320, 844))
UPSTREAM_GLAZE_SHA = "94e0db139da2b9a3f7ead7744cbcd0ad9d7627bd"


class BrowserError(RuntimeError):
    pass


def require(ok: bool, message: str) -> None:
    if not ok:
        raise BrowserError(message)


def req(method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
    data = None if payload is None else json.dumps(payload).encode()
    with urlopen(Request(BASE + path, data=data, method=method, headers={"Content-Type": "application/json"}), timeout=25) as response:
        raw = response.read()
    if not raw:
        return None
    value = json.loads(raw.decode()).get("value")
    if isinstance(value, dict) and value.get("error"):
        raise BrowserError(f"{value.get('error')}: {value.get('message', '')}")
    return value


def wait(url: str, driver: bool = False) -> None:
    end = time.monotonic() + 15
    last: Exception | None = None
    while time.monotonic() < end:
        try:
            if driver:
                state = req("GET", "/status")
                if isinstance(state, dict) and state.get("ready"):
                    return
            else:
                with urlopen(url, timeout=1) as response:
                    if response.status == 200:
                        return
        except Exception as exc:
            last = exc
        time.sleep(.15)
    raise BrowserError(f"service not ready: {last}")


def driver_bin() -> str:
    for candidate in (shutil.which("chromedriver"), "/usr/local/share/chromedriver-linux64/chromedriver"):
        if candidate and Path(candidate).is_file():
            return str(candidate)
    raise BrowserError("chromedriver unavailable")


def main() -> int:
    server = driver = None
    session: str | None = None
    log_path: str | None = None
    evidence_dir_raw = os.environ.get("WARDVEIL_V12_SCREENSHOT_DIR", "").strip()
    evidence_dir = Path(evidence_dir_raw) if evidence_dir_raw else None
    evidence_sha = os.environ.get("WARDVEIL_EVIDENCE_SHA", "").strip() or "local"
    captures: list[dict[str, Any]] = []
    try:
        require((SITE / "index.html").is_file(), "evaluation build missing; run validate_v1_2_evaluation.py first")
        if evidence_dir:
            require(
                evidence_sha == "local" or (len(evidence_sha) == 40 and all(c in "0123456789abcdef" for c in evidence_sha.lower())),
                f"invalid exact evidence source revision: {evidence_sha}",
            )
            if evidence_dir.exists():
                shutil.rmtree(evidence_dir)
            evidence_dir.mkdir(parents=True)

        server = subprocess.Popen(
            ["python3", "-m", "http.server", str(WEB_PORT), "--bind", "127.0.0.1", "--directory", str(SITE)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        wait(TARGET)
        with tempfile.NamedTemporaryFile(prefix="wardveil-v12-chromedriver-", suffix=".log", delete=False) as log:
            log_path = log.name
            driver = subprocess.Popen([driver_bin(), f"--port={DRIVER_PORT}", "--allowed-ips=127.0.0.1"], stdout=log, stderr=subprocess.STDOUT)
        wait(BASE + "/status", True)
        value = req(
            "POST",
            "/session",
            {"capabilities": {"alwaysMatch": {"browserName": "chrome", "goog:chromeOptions": {"args": ["--headless=new", "--no-sandbox", "--disable-dev-shm-usage", "--disable-background-networking", "--disable-extensions", "--no-first-run", "--window-size=1180,900"]}}}},
        )
        require(isinstance(value, dict) and isinstance(value.get("sessionId"), str), f"bad Chrome session: {value!r}")
        session = value["sessionId"]
        req("POST", f"/session/{session}/timeouts", {"implicit": 0, "pageLoad": 15000, "script": 10000})
        req("POST", f"/session/{session}/url", {"url": TARGET})

        initial = req(
            "POST",
            f"/session/{session}/execute/sync",
            {"script": """const r=document.documentElement,h=document.querySelector('.glz12-evaluation-glaze'),cards=[...document.querySelectorAll('[data-glaze-material-level=surface]')];const hs=getComputedStyle(h);return {upgrade:r.dataset.glazeUpgrade,candidate:document.querySelector('meta[name=goreecloud-glaze-ui-candidate]')?.content||'',blur:hs.backdropFilter||hs.webkitBackdropFilter||'',cards:cards.length,blurredCards:cards.filter(x=>{const s=getComputedStyle(x);const b=s.backdropFilter||s.webkitBackdropFilter||'none';return b&&b!=='none'}).length,bg:hs.backgroundColor};""", "args": []},
        )
        require(isinstance(initial, dict), "candidate state unreadable")
        require(initial.get("upgrade") == "v1.2-frosted-neutral", f"candidate activation missing: {initial}")
        require(initial.get("candidate") == "1.2.0-candidate", f"candidate metadata missing: {initial}")
        require("blur" in str(initial.get("blur", "")), f"candidate header is not exercising backdrop blur: {initial}")
        require(int(initial.get("cards", 0)) >= 8, f"expected solid security surfaces missing: {initial}")
        require(int(initial.get("blurredCards", -1)) == 0, f"security-reading surfaces acquired backdrop blur: {initial}")

        for requested, height in VIEWPORTS:
            req("POST", f"/session/{session}/window/rect", {"width": requested, "height": height, "x": 0, "y": 0})
            state = req(
                "POST",
                f"/session/{session}/execute/sync",
                {"script": """const h=document.querySelector('header'),m=document.querySelector('main'),nav=document.querySelector('header nav');const hr=h?.getBoundingClientRect(),mr=m?.getBoundingClientRect(),ns=nav?getComputedStyle(nav):null;const links=[...document.querySelectorAll('header nav a')].map(x=>x.getBoundingClientRect()).filter(r=>r.width>0&&r.height>0);return {ready:document.readyState,w:innerWidth,sw:document.documentElement.scrollWidth,pos:h?getComputedStyle(h).position:'',hb:hr?.bottom||0,hh:hr?.height||0,mt:mr?.top||0,minNav:links.length?Math.min(...links.map(r=>r.height)):0,navDisplay:ns?.display||'',navOverflowX:ns?.overflowX||''};""", "args": []},
            )
            require(isinstance(state, dict), f"layout unreadable at {requested}px")
            width = int(state.get("w", requested))
            require(state.get("ready") == "complete", f"page incomplete at {width}px: {state}")
            require(int(state.get("sw", width + 2)) <= width + 1, f"horizontal overflow at {width}px: {state}")
            require(state.get("pos") not in {"sticky", "fixed"}, f"evaluation header overlays content at {width}px: {state}")
            require(float(state.get("mt", 0)) + 1 >= float(state.get("hb", 0)), f"main overlaps header at {width}px: {state}")
            require(float(state.get("minNav", 0)) >= 47.5, f"navigation target below 48px at {width}px: {state}")
            if width <= 390:
                require(float(state.get("hh", 999)) <= 190, f"mobile evaluation header consumes excessive viewport height at {width}px: {state}")
                require(state.get("navDisplay") == "flex", f"mobile candidate navigation must be a compact flex capsule at {width}px: {state}")
                require(state.get("navOverflowX") in {"auto", "scroll"}, f"mobile candidate navigation must scroll horizontally at {width}px: {state}")

        reduced = req(
            "POST",
            f"/session/{session}/execute/sync",
            {"script": """document.documentElement.dataset.glzTransparency='reduced';const h=document.querySelector('.glz12-evaluation-glaze');const s=getComputedStyle(h);return {blur:s.backdropFilter||s.webkitBackdropFilter||'none',bg:s.backgroundColor};""", "args": []},
        )
        require(isinstance(reduced, dict) and reduced.get("blur") == "none", f"Reduced Transparency did not remove backdrop blur: {reduced}")

        deep_dark = req(
            "POST",
            f"/session/{session}/execute/sync",
            {"script": """const r=document.documentElement;r.dataset.glzAppearance='deep-dark';r.dataset.theme='dark';delete r.dataset.glzTransparency;const h=document.querySelector('.glz12-evaluation-glaze'),card=document.querySelector('[data-glaze-material-level=surface]');return {appearance:r.dataset.glzAppearance,productTheme:r.dataset.theme,bg:getComputedStyle(h).backgroundColor,surface:getComputedStyle(card).backgroundColor,text:getComputedStyle(card).color};""", "args": []},
        )
        require(isinstance(deep_dark, dict) and deep_dark.get("appearance") == "deep-dark", f"Deep Dark mapping failed: {deep_dark}")
        require(deep_dark.get("productTheme") == "dark", f"Deep Dark did not activate Wardveil product dark theme: {deep_dark}")
        require("255, 255, 255" not in str(deep_dark.get("surface", "")), f"Deep Dark left a light Security Center surface active: {deep_dark}")

        def capture(name: str, width: int, height: int, appearance: str, reduced_transparency: bool = False) -> None:
            if not evidence_dir:
                return
            req("POST", f"/session/{session}/window/rect", {"width": width, "height": height, "x": 0, "y": 0})
            state = req(
                "POST",
                f"/session/{session}/execute/sync",
                {
                    "script": """const r=document.documentElement;const appearance=arguments[0],reduced=arguments[1];if(appearance==='system'){delete r.dataset.glzAppearance;delete r.dataset.theme;}else{r.dataset.glzAppearance=appearance;r.dataset.theme=appearance==='light'?'light':'dark';}if(reduced)r.dataset.glzTransparency='reduced';else delete r.dataset.glzTransparency;const button=document.querySelector('[data-theme-toggle]');const label=appearance==='deep-dark'?'Deep Dark':appearance==='system'?'System':appearance.charAt(0).toUpperCase()+appearance.slice(1);if(button){button.textContent=label;button.setAttribute('aria-label',`Appearance: ${label}. Review capture state.`);}window.scrollTo(0,0);const h=document.querySelector('.glz12-evaluation-glaze'),card=document.querySelector('[data-glaze-material-level=surface]'),s=getComputedStyle(h);return {appearance:r.dataset.glzAppearance||'system',productTheme:r.dataset.theme||'system',transparency:r.dataset.glzTransparency||'standard',background:s.backgroundColor,blur:s.backdropFilter||s.webkitBackdropFilter||'none',surfaceBackground:getComputedStyle(card).backgroundColor,width:innerWidth,height:innerHeight,label:button?.textContent||''};""",
                    "args": [appearance, reduced_transparency],
                },
            )
            require(isinstance(state, dict), f"capture state unreadable: {name}")
            expected_product_theme = "light" if appearance == "light" else "dark" if appearance in {"dark", "deep-dark"} else "system"
            require(state.get("productTheme") == expected_product_theme, f"capture product theme does not match appearance for {name}: {state}")
            if appearance in {"dark", "deep-dark"}:
                require("255, 255, 255" not in str(state.get("surfaceBackground", "")), f"dark capture contains a light Security Center surface: {name}: {state}")
            encoded = req("GET", f"/session/{session}/screenshot")
            require(isinstance(encoded, str) and encoded, f"screenshot unavailable: {name}")
            image = base64.b64decode(encoded)
            require(image.startswith(b"\x89PNG\r\n\x1a\n"), f"screenshot is not PNG: {name}")
            path = evidence_dir / f"{name}.png"
            path.write_bytes(image)
            captures.append(
                {
                    "file": path.name,
                    "sha256": hashlib.sha256(image).hexdigest(),
                    "bytes": len(image),
                    "viewport": [width, height],
                    "appearance": state.get("appearance"),
                    "product_theme": state.get("productTheme"),
                    "transparency": state.get("transparency"),
                    "appearance_label": state.get("label"),
                    "header_background": state.get("background"),
                    "header_backdrop_filter": state.get("blur"),
                    "surface_background": state.get("surfaceBackground"),
                }
            )

        capture("01-light-desktop", 1180, 900, "light")
        capture("02-light-mobile", 390, 844, "light")
        capture("03-dark-desktop", 1180, 900, "dark")
        capture("04-deep-dark-desktop", 1180, 900, "deep-dark")
        capture("05-reduced-transparency-desktop", 1180, 900, "light", True)

        if evidence_dir:
            require(len(captures) == 5, f"expected five optical-review captures, got {len(captures)}")
            manifest = {
                "schema": "goreecloud.wardveil.glaze-v1.2-evaluation-evidence/v1",
                "non_production": True,
                "upstream_glaze_candidate_revision": UPSTREAM_GLAZE_SHA,
                "wardveil_source_revision": evidence_sha,
                "capture_count": len(captures),
                "captures": captures,
                "acceptance_boundary": "Automated screenshots are review evidence only; they do not establish human optical approval or production acceptance.",
            }
            (evidence_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

        print(
            "Wardveil GLAZE UI V1.2 evaluation Chrome smoke passed: bounded frosted header, solid security surfaces, "
            "compact mobile navigation, synchronized Wardveil/Glaze appearance state, responsive geometry, Reduced Transparency, Deep Dark"
            + (", five deterministic optical-review screenshots captured." if evidence_dir else ".")
        )
        return 0
    except Exception as exc:
        print(f"Wardveil GLAZE UI V1.2 evaluation Chrome smoke failed: {exc}")
        if log_path:
            try:
                print(Path(log_path).read_text(errors="replace")[-6000:])
            except OSError:
                pass
        return 1
    finally:
        if session:
            try:
                req("DELETE", f"/session/{session}")
            except Exception:
                pass
        for process in (driver, server):
            if process:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        if log_path:
            try:
                Path(log_path).unlink()
            except OSError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
