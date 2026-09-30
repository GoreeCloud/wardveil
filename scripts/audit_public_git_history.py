#!/usr/bin/env python3
"""Fail-closed scan of retained public Git history for credential-shaped secrets.

The scanner reports only category/object/path metadata. It never prints a matched
secret value. It scans every blob reachable from refs present in the local clone;
CI is responsible for fetching retained public branch and tag heads first. Untrusted external pull-request refs are deliberately excluded from this required check.
"""

from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass


MAX_BLOB_BYTES = 10 * 1024 * 1024


@dataclass(frozen=True)
class Detector:
    name: str
    pattern: re.Pattern[bytes]


DETECTORS = (
    Detector("private-key", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    Detector("github-token", re.compile(rb"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b")),
    Detector("aws-access-key", re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    Detector("google-api-key", re.compile(rb"\bAIza[0-9A-Za-z_-]{30,}\b")),
    Detector("google-oauth-secret", re.compile(rb"\bGOCSPX-[0-9A-Za-z_-]{20,}\b")),
    Detector("slack-token", re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    Detector("stripe-secret", re.compile(rb"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    Detector("sendgrid-key", re.compile(rb"\bSG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    Detector("npm-token", re.compile(rb"\bnpm_[A-Za-z0-9]{20,}\b")),
    Detector("pypi-token", re.compile(rb"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{20,}\b")),
    Detector("jwt", re.compile(rb"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    Detector("basic-auth-url", re.compile(rb"https?://[^/\s:@]+:[^@\s/]+@")),
)

# Deliberate validation fixtures. Construct the matched byte strings in pieces so
# this scanner's current source does not itself contain a detector match.
BASIC_AUTH_FIXTURE_PREFIX = b"https://" + b"user:" + b"pass@"
PRIVATE_KEY_MARKER = b"-----BEGIN " + b"PRIVATE KEY-----"
RSA_PRIVATE_KEY_MARKER = b"-----BEGIN RSA " + b"PRIVATE KEY-----"

ALLOWED_EXACT_MATCHES = {
    ("basic-auth-url", "scripts/test_wardveil_mesh_delivery.py", BASIC_AUTH_FIXTURE_PREFIX),
    ("basic-auth-url", "scripts/audit_public_git_history.py", BASIC_AUTH_FIXTURE_PREFIX),
    ("private-key", "scripts/validate_wardveil.py", PRIVATE_KEY_MARKER),
    ("private-key", "scripts/validate_wardveil.py", RSA_PRIVATE_KEY_MARKER),
}


def run(*args: str, input_bytes: bytes | None = None) -> bytes:
    completed = subprocess.run(
        args,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        raise SystemExit(f"history audit command failed: {' '.join(args)}: {stderr}")
    return completed.stdout


def object_inventory() -> tuple[dict[str, str], dict[str, tuple[str, int]]]:
    listed = run("git", "rev-list", "--objects", "--all").decode("utf-8", errors="replace")
    paths: dict[str, str] = {}
    shas: list[str] = []
    for line in listed.splitlines():
        if not line:
            continue
        sha, _, path = line.partition(" ")
        shas.append(sha)
        if path:
            paths.setdefault(sha, path)

    if not shas:
        raise SystemExit("history audit found no reachable Git objects")

    query = ("\n".join(shas) + "\n").encode()
    checked = run(
        "git",
        "cat-file",
        "--batch-check=%(objectname) %(objecttype) %(objectsize)",
        input_bytes=query,
    ).decode("utf-8", errors="replace")

    metadata: dict[str, tuple[str, int]] = {}
    for line in checked.splitlines():
        sha, object_type, size_text = line.split(" ", 2)
        metadata[sha] = (object_type, int(size_text))
    return paths, metadata


def is_allowed(detector: str, path: str, matched: bytes) -> bool:
    return (detector, path, matched) in ALLOWED_EXACT_MATCHES


def git_ref_map(prefix: str) -> dict[str, str]:
    raw = run(
        "git",
        "for-each-ref",
        "--format=%(refname) %(objectname)",
        prefix,
    ).decode("utf-8", errors="replace")
    refs: dict[str, str] = {}
    for line in raw.splitlines():
        refname, _, sha = line.partition(" ")
        if refname and sha:
            refs[refname] = sha
    return refs


def is_ancestor(ancestor: str, descendant: str) -> bool:
    completed = subprocess.run(
        ("git", "merge-base", "--is-ancestor", ancestor, descendant),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode == 0:
        return True
    if completed.returncode == 1:
        return False
    stderr = completed.stderr.decode("utf-8", errors="replace").strip()
    raise SystemExit(
        f"history audit ancestry check failed: {ancestor} -> {descendant}: {stderr}"
    )


def report_public_ref_inventory() -> None:
    remote_prefix = "refs/remotes/origin/"
    branch_refs = {
        ref: sha
        for ref, sha in git_ref_map("refs/remotes/origin").items()
        if ref != "refs/remotes/origin/HEAD"
    }
    tag_refs = git_ref_map("refs/tags")
    main_ref = "refs/remotes/origin/main"
    main_sha = branch_refs.get(main_ref)
    if not main_sha:
        raise SystemExit(
            "history audit cannot classify public refs: refs/remotes/origin/main is missing"
        )

    non_main = {ref: sha for ref, sha in branch_refs.items() if ref != main_ref}
    by_tip: dict[str, list[str]] = {}
    for ref, sha in branch_refs.items():
        by_tip.setdefault(sha, []).append(ref)
    duplicate_groups = [
        (sha, sorted(refs))
        for sha, refs in by_tip.items()
        if len(refs) > 1
    ]

    merged: list[tuple[str, str]] = []
    diverged: list[tuple[str, str]] = []
    for ref, sha in sorted(non_main.items()):
        if is_ancestor(sha, main_sha):
            merged.append((ref, sha))
        else:
            diverged.append((ref, sha))

    print(
        "Wardveil public ref inventory: "
        f"{len(branch_refs)} branches, {len(tag_refs)} tags, "
        f"{len(duplicate_groups)} duplicate-tip groups, "
        f"{len(merged)} non-main branches fully contained in main, "
        f"{len(diverged)} non-main branches diverged from main."
    )
    for sha, refs in sorted(duplicate_groups):
        names = ",".join(ref.removeprefix(remote_prefix) for ref in refs)
        print(f"duplicate-tip tip={sha} branches={names}")
    for ref, sha in diverged:
        print(
            "diverged-branch "
            f"ref={ref.removeprefix(remote_prefix)} tip={sha}"
        )


def scan() -> int:
    paths, metadata = object_inventory()
    findings: list[tuple[str, str, str]] = []
    blobs_scanned = 0
    bytes_scanned = 0
    oversized_blobs: list[tuple[str, str, int]] = []

    for sha, (object_type, size) in metadata.items():
        if object_type != "blob":
            continue

        path = paths.get(sha, "<path-unresolved>")
        if size > MAX_BLOB_BYTES:
            oversized_blobs.append((sha, path, size))
            continue

        blob = run("git", "cat-file", "blob", sha)
        blobs_scanned += 1
        bytes_scanned += len(blob)

        for detector in DETECTORS:
            for match in detector.pattern.finditer(blob):
                matched = match.group(0)
                if is_allowed(detector.name, path, matched):
                    continue
                findings.append((detector.name, sha, path))

    refs = run("git", "for-each-ref", "--format=%(refname)").decode().splitlines()
    print(
        "Wardveil public Git history audit: "
        f"{len(refs)} refs, {blobs_scanned} blobs, {bytes_scanned} bytes scanned."
    )
    report_public_ref_inventory()

    if oversized_blobs:
        print("History audit cannot claim completeness: oversized blobs were skipped.", file=sys.stderr)
        for sha, path, size in oversized_blobs:
            print(f"oversized-blob object={sha} path={path} bytes={size}", file=sys.stderr)
        return 2

    if findings:
        print(
            "Credential-shaped findings detected. Values are intentionally suppressed.",
            file=sys.stderr,
        )
        for category, sha, path in sorted(set(findings)):
            print(f"finding category={category} object={sha} path={path}", file=sys.stderr)
        return 1

    print("Wardveil retained public Git history contains no detected credential-shaped secrets.")
    return 0


if __name__ == "__main__":
    raise SystemExit(scan())
