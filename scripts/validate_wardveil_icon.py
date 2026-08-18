#!/usr/bin/env python3
"""Validate the eventual canonical Wardveil SVG without third-party dependencies."""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CANONICAL_ICON_PATH = ROOT / "branding/wardveil-security-icon.svg"
IDENTITY_CONTRACT_PATH = ROOT / "contracts/wardveil.identity.json"
SVG_NAMESPACE = "http://www.w3.org/2000/svg"
XLINK_NAMESPACE = "http://www.w3.org/1999/xlink"
XML_NAMESPACE = "http://www.w3.org/XML/1998/namespace"
MAX_SVG_BYTES = 256 * 1024
MAX_ELEMENTS = 512
MAX_DEPTH = 32
ID_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:-]*$")
URL_FUNCTION_PATTERN = re.compile(r"url\(\s*(['\"]?)(.*?)\1\s*\)", re.IGNORECASE)
FORBIDDEN_URI_SCHEMES = re.compile(r"^(?:https?|data|javascript|file|ftp):", re.IGNORECASE)

ALLOWED_ELEMENTS = {
    "svg",
    "g",
    "defs",
    "symbol",
    "path",
    "circle",
    "ellipse",
    "rect",
    "line",
    "polyline",
    "polygon",
    "linearGradient",
    "radialGradient",
    "stop",
    "clipPath",
    "mask",
    "use",
    "title",
    "desc",
}

FORBIDDEN_ELEMENTS = {
    "script",
    "style",
    "foreignObject",
    "image",
    "iframe",
    "audio",
    "video",
    "canvas",
    "text",
    "font",
    "font-face",
    "animate",
    "animateMotion",
    "animateTransform",
    "set",
    "filter",
}


class ValidationError(ValueError):
    """Raised when the canonical SVG violates Wardveil asset policy."""


def fail(message: str) -> None:
    raise ValidationError(message)


def split_qname(name: str) -> tuple[str | None, str]:
    if name.startswith("{") and "}" in name:
        namespace, local = name[1:].split("}", 1)
        return namespace, local
    return None, name


def parse_view_box(value: str) -> tuple[float, float, float, float]:
    parts = value.replace(",", " ").split()
    if len(parts) != 4:
        fail("canonical SVG viewBox must contain exactly four numbers")
    try:
        numbers = tuple(float(part) for part in parts)
    except ValueError as exc:
        fail("canonical SVG viewBox contains a non-numeric value")
        raise AssertionError from exc

    if not all(math.isfinite(number) for number in numbers):
        fail("canonical SVG viewBox values must be finite")

    _, _, width, height = numbers
    if width <= 0 or height <= 0:
        fail("canonical SVG viewBox width and height must be positive")
    if width > 8192 or height > 8192:
        fail("canonical SVG viewBox is unreasonably large")
    return numbers  # type: ignore[return-value]


def validate_local_reference(value: str, context: str, references: set[str]) -> None:
    value = value.strip().strip("'\"")
    if not value:
        fail(f"{context} contains an empty reference")
    if FORBIDDEN_URI_SCHEMES.match(value):
        fail(f"{context} contains an external or executable URI")
    if not value.startswith("#"):
        fail(f"{context} must use an internal #fragment reference")
    reference = value[1:]
    if not reference or not ID_PATTERN.fullmatch(reference):
        fail(f"{context} contains an invalid internal fragment identifier")
    references.add(reference)


def validate_style_value(value: str, context: str, references: set[str]) -> None:
    lowered = value.lower()
    if "@import" in lowered or "expression(" in lowered:
        fail(f"{context} contains forbidden CSS behavior")
    for match in URL_FUNCTION_PATTERN.finditer(value):
        validate_local_reference(match.group(2), context, references)
    scrubbed = URL_FUNCTION_PATTERN.sub("", value).strip()
    if re.search(r"(?:https?|data|javascript|file|ftp):", scrubbed, re.IGNORECASE):
        fail(f"{context} contains an external or executable URI")


def validate_svg_text(text: str, source: str = "canonical SVG") -> None:
    if not text.strip():
        fail(f"{source} is empty")

    lowered = text.lower()
    if "<!doctype" in lowered or "<!entity" in lowered:
        fail(f"{source} must not contain DTD or entity declarations")

    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        fail(f"{source} is not well-formed XML: {exc}")
        raise AssertionError from exc

    root_namespace, root_local = split_qname(root.tag)
    if root_local != "svg" or root_namespace != SVG_NAMESPACE:
        fail(f"{source} root must be an SVG element in the canonical SVG namespace")

    view_box = root.attrib.get("viewBox")
    if not view_box:
        fail(f"{source} must declare a viewBox")
    parse_view_box(view_box)

    ids: set[str] = set()
    references: set[str] = set()
    element_count = 0

    def visit(element: ET.Element, depth: int) -> None:
        nonlocal element_count
        element_count += 1
        if element_count > MAX_ELEMENTS:
            fail(f"{source} exceeds the {MAX_ELEMENTS}-element complexity limit")
        if depth > MAX_DEPTH:
            fail(f"{source} exceeds the {MAX_DEPTH}-level nesting limit")

        namespace, local = split_qname(element.tag)
        if namespace != SVG_NAMESPACE:
            fail(f"{source} contains a foreign-namespace element: {local}")
        if local in FORBIDDEN_ELEMENTS or local.startswith("fe"):
            fail(f"{source} contains forbidden active, raster, text, animation, or filter element: {local}")
        if local not in ALLOWED_ELEMENTS:
            fail(f"{source} contains unsupported SVG element: {local}")

        if local not in {"title", "desc"} and element.text and element.text.strip():
            fail(f"{source} contains unexpected text content in <{local}>")
        if local in {"title", "desc"} and element.text:
            if re.search(r"(?:https?|data|javascript|file|ftp):", element.text, re.IGNORECASE):
                fail(f"{source} title/description must not contain external URI content")

        for raw_name, raw_value in element.attrib.items():
            attr_namespace, attr_local = split_qname(raw_name)
            value = raw_value.strip()

            if attr_namespace not in {None, XLINK_NAMESPACE, XML_NAMESPACE}:
                fail(f"{source} contains an unsupported attribute namespace: {attr_local}")
            if attr_local.lower().startswith("on"):
                fail(f"{source} contains an event-handler attribute: {attr_local}")
            if attr_local in {"base", "xml:base"}:
                fail(f"{source} must not redefine an XML base URI")

            if attr_local == "id":
                if not ID_PATTERN.fullmatch(value):
                    fail(f"{source} contains an invalid SVG id: {value!r}")
                if value in ids:
                    fail(f"{source} contains duplicate SVG id: {value}")
                ids.add(value)

            if attr_local == "href":
                validate_local_reference(value, f"{source} href", references)
            elif attr_local == "style":
                validate_style_value(value, f"{source} style", references)
            else:
                for match in URL_FUNCTION_PATTERN.finditer(value):
                    validate_local_reference(match.group(2), f"{source} {attr_local}", references)
                scrubbed = URL_FUNCTION_PATTERN.sub("", value).strip()
                if re.search(r"(?:https?|data|javascript|file|ftp):", scrubbed, re.IGNORECASE):
                    fail(f"{source} attribute {attr_local} contains an external or executable URI")

        for child in element:
            visit(child, depth + 1)
            if child.tail and child.tail.strip():
                fail(f"{source} contains unexpected mixed text content")

    visit(root, 1)

    missing_ids = sorted(references - ids)
    if missing_ids:
        fail(f"{source} contains dangling internal references: {', '.join(missing_ids)}")


def validate_svg_file(path: Path) -> None:
    try:
        size = path.stat().st_size
    except OSError as exc:
        fail(f"unable to stat canonical SVG: {exc}")
        raise AssertionError from exc
    if size <= 0:
        fail("canonical SVG is empty")
    if size > MAX_SVG_BYTES:
        fail(f"canonical SVG exceeds the {MAX_SVG_BYTES}-byte size limit")
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        fail("canonical SVG must be UTF-8 text")
        raise AssertionError from exc
    validate_svg_text(text, str(path.relative_to(ROOT)))


def load_visual_status() -> tuple[str, str]:
    try:
        contract = json.loads(IDENTITY_CONTRACT_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"unable to read Wardveil identity contract: {exc}")
        raise AssertionError from exc
    visual = contract.get("visual_identity")
    if not isinstance(visual, dict):
        fail("identity contract is missing visual_identity metadata")
    return str(visual.get("canonical_visual_identity_status")), str(visual.get("showcase_status"))


def validate_repository_icon_state() -> None:
    icon_exists = CANONICAL_ICON_PATH.is_file()
    visual_status, showcase_status = load_visual_status()

    if not icon_exists:
        if visual_status != "pending-canonical-icon" or showcase_status != "blocked-pending-canonical-icon":
            fail("canonical icon is absent but the machine-readable showcase gate is not blocked")
        print("Wardveil icon validation: canonical icon is pending; showcase remains blocked.")
        return

    if visual_status != "approved" or showcase_status != "approved":
        fail("canonical icon asset exists without explicit machine-readable approval")
    validate_svg_file(CANONICAL_ICON_PATH)
    print("Wardveil icon validation: approved canonical SVG passes security and portability checks.")


def expect_invalid(name: str, svg: str) -> None:
    try:
        validate_svg_text(svg, name)
    except ValidationError:
        return
    fail(f"self-test fixture unexpectedly passed: {name}")


def run_self_tests() -> None:
    valid = f'''<svg xmlns="{SVG_NAMESPACE}" viewBox="0 0 64 64">
  <defs><linearGradient id="veil" x1="0" y1="0" x2="1" y2="1"><stop offset="0"/><stop offset="1"/></linearGradient></defs>
  <path id="left" d="M8 8 L30 32 L8 56 Z" fill="url(#veil)"/>
  <path d="M56 8 L34 32 L56 56 Z"/>
  <circle cx="32" cy="32" r="4"/>
</svg>'''
    validate_svg_text(valid, "valid fixture")

    expect_invalid("doctype fixture", f'<!DOCTYPE svg><svg xmlns="{SVG_NAMESPACE}" viewBox="0 0 1 1"/>')
    expect_invalid("script fixture", f'<svg xmlns="{SVG_NAMESPACE}" viewBox="0 0 1 1"><script/></svg>')
    expect_invalid("raster fixture", f'<svg xmlns="{SVG_NAMESPACE}" viewBox="0 0 1 1"><image href="data:image/png;base64,AA=="/></svg>')
    expect_invalid("external href fixture", f'<svg xmlns="{SVG_NAMESPACE}" viewBox="0 0 1 1"><use href="https://example.invalid/a.svg#x"/></svg>')
    expect_invalid("event fixture", f'<svg xmlns="{SVG_NAMESPACE}" viewBox="0 0 1 1" onload="alert(1)"/>')
    expect_invalid("duplicate id fixture", f'<svg xmlns="{SVG_NAMESPACE}" viewBox="0 0 1 1"><path id="x"/><circle id="x"/></svg>')
    expect_invalid("dangling reference fixture", f'<svg xmlns="{SVG_NAMESPACE}" viewBox="0 0 1 1"><path fill="url(#missing)"/></svg>')
    expect_invalid("missing viewBox fixture", f'<svg xmlns="{SVG_NAMESPACE}"><path/></svg>')
    expect_invalid("text fixture", f'<svg xmlns="{SVG_NAMESPACE}" viewBox="0 0 1 1"><text>W</text></svg>')
    expect_invalid("foreign namespace fixture", f'<svg xmlns="{SVG_NAMESPACE}" xmlns:h="http://www.w3.org/1999/xhtml" viewBox="0 0 1 1"><h:div/></svg>')
    print("Wardveil icon validator self-tests passed.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="run deterministic validator fixtures")
    args = parser.parse_args()

    try:
        if args.self_test:
            run_self_tests()
        else:
            validate_repository_icon_state()
    except ValidationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
