#!/usr/bin/env python3
"""Validate the non-authorizing Wardveil 2.0 release-evidence template."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "qualification" / "release-evidence.template.json"
CANDIDATE = ROOT / "qualification" / "seal-candidate.json"
READINESS = ROOT / "qualification" / "seal-readiness.json"

PENDING_OBJECTS = ("published_release", "artifact", "provenance", "deployment", "rollback", "verification")


def fail(message: str) -> None:
    raise SystemExit(f"Wardveil release-evidence template validation failed: {message}")


def main() -> None:
    record = json.loads(TEMPLATE.read_text())
    candidate = json.loads(CANDIDATE.read_text())
    readiness = json.loads(READINESS.read_text())

    if record.get("schema_version") != 1 or record.get("component") != "Wardveil Security":
        fail("template identity/schema drifted")
    if record.get("version") != "2.0.0" or record.get("candidate_id") != candidate.get("candidate_id"):
        fail("template must bind the current Version 2.0 Seal candidate")
    if record.get("candidate_source_revision") != candidate.get("source_revision"):
        fail("template source revision must match the Seal candidate")
    if record.get("status") != "pending":
        fail("template must remain pending until a separate accepted release record exists")
    if record.get("production_approved") is not False or record.get("authority_effect") != "none":
        fail("template must remain non-authorizing")

    for name in PENDING_OBJECTS:
        value = record.get(name)
        if not isinstance(value, dict) or value.get("status") != "pending":
            fail(f"{name} must remain a pending object")

    release = record["published_release"]
    for key in ("tag", "release_url", "published_at"):
        if release.get(key) is not None:
            fail(f"published_release.{key} must remain null in the template")

    artifact = record["artifact"]
    for key in ("name", "digest_sha256", "package_identity"):
        if artifact.get(key) is not None:
            fail(f"artifact.{key} must remain null in the template")

    for part in ("sbom", "signing", "source_attestation"):
        obj = record["provenance"].get(part)
        if not isinstance(obj, dict) or obj.get("status") != "pending":
            fail(f"provenance.{part} must remain pending")
        for key in ("identity", "digest_sha256"):
            if obj.get(key) is not None:
                fail(f"provenance.{part}.{key} must remain null in the template")

    deployment = record["deployment"]
    for key in ("revision", "identity", "environment", "observed_at"):
        if deployment.get(key) is not None:
            fail(f"deployment.{key} must remain null in the template")

    rollback = record["rollback"]
    if rollback.get("target_source_revision") != candidate.get("rollback_target"):
        fail("rollback target must match the candidate rollback target")
    if rollback.get("target_artifact_digest_sha256") is not None or rollback.get("observed_at") is not None:
        fail("rollback artifact/observation must remain null in the template")
    if rollback.get("exercise_status") != "pending":
        fail("rollback exercise must remain pending")

    verification = record["verification"]
    if verification.get("canonical_readback_status") != "pending":
        fail("canonical readback must remain pending")
    if verification.get("post_release_checks") != []:
        fail("post-release checks must remain empty in the template")

    gate = next((g for g in readiness.get("gates", []) if g.get("id") == "release-provenance-rollback"), None)
    if not gate or gate.get("state") != "blocked":
        fail("release-provenance-rollback must remain blocked while only the template exists")
    if "qualification/release-evidence.template.json" not in gate.get("evidence", []):
        fail("readiness gate must cite the release-evidence template")

    source = record.get("candidate_source_revision", "")
    if not re.fullmatch(r"[0-9a-f]{40}", source):
        fail("candidate source revision must be an exact SHA")

    print("Wardveil release-evidence template guard passed: evidence shape is defined and remains pending/non-authorizing.")


if __name__ == "__main__":
    main()
