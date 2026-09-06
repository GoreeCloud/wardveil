#!/usr/bin/env python3
"""Exercise Wardveil's isolated V1.2 evaluation in headless Chrome."""
from __future__ import annotations

import json
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
    try:
        require((SITE / "index.html").is_file(), "evaluation build missing; run validate_v1_2_evaluation.py first")
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
                {"script": """const h=document.querySelector('header'),m=document.querySelector('main');const hr=h?.getBoundingClientRect(),mr=m?.getBoundingClientRect();const links=[...document.querySelectorAll('header nav a')].map(x=>x.getBoundingClientRect()).filter(r=>r.width>0&&r.height>0);return {ready:document.readyState,w:innerWidth,sw:document.documentElement.scrollWidth,pos:h?getComputedStyle(h).position:'',hb:hr?.bottom||0,mt:mr?.top||0,minNav:links.length?Math.min(...links.map(r=>r.height)):0};""", "args": []},
            )
            require(isinstance(state, dict), f"layout unreadable at {requested}px")
            width = int(state.get("w", requested))
            require(state.get("ready") == "complete", f"page incomplete at {width}px: {state}")
            require(int(state.get("sw", width + 2)) <= width + 1, f"horizontal overflow at {width}px: {state}")
            require(state.get("pos") not in {"sticky", "fixed"}, f"evaluation header overlays content at {width}px: {state}")
            require(float(state.get("mt", 0)) + 1 >= float(state.get("hb", 0)), f"main overlaps header at {width}px: {state}")
            require(float(state.get("minNav", 0)) >= 47.5, f"navigation target below 48px at {width}px: {state}")

        reduced = req(
            "POST",
            f"/session/{session}/execute/sync",
            {"script": """document.documentElement.dataset.glzTransparency='reduced';const h=document.querySelector('.glz12-evaluation-glaze');const s=getComputedStyle(h);return {blur:s.backdropFilter||s.webkitBackdropFilter||'none',bg:s.backgroundColor};""", "args": []},
        )
        require(isinstance(reduced, dict) and reduced.get("blur") == "none", f"Reduced Transparency did not remove backdrop blur: {reduced}")

        deep_dark = req(
            "POST",
            f"/session/{session}/execute/sync",
            {"script": """delete document.documentElement.dataset.glzTransparency;document.documentElement.dataset.glzAppearance='deep-dark';const h=document.querySelector('.glz12-evaluation-glaze');return {appearance:document.documentElement.dataset.glzAppearance,bg:getComputedStyle(h).backgroundColor};""", "args": []},
        )
        require(isinstance(deep_dark, dict) and deep_dark.get("appearance") == "deep-dark", f"Deep Dark mapping failed: {deep_dark}")

        print("Wardveil GLAZE UI V1.2 evaluation Chrome smoke passed: bounded frosted header, solid security surfaces, responsive geometry, Reduced Transparency, Deep Dark.")
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
