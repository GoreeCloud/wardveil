#!/usr/bin/env python3
"""Validate Wardveil's exact Seal candidate while keeping Anchor qualification fail closed."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RECORD = ROOT / "qualification" / "seal-readiness.json"
CANDIDATE = ROOT / "qualification" / "seal-candidate.json"
MANIFEST = ROOT / "goreecloud.platform.yaml"
RUNTIME = ROOT / "contracts" / "wardveil.cloudflare.runtime-acceptance.json"
RUNTIME_TEMPLATE = ROOT / "evidence" / "wardveil.cloudflare.production.template.json"
RESTORE = ROOT / "contracts" / "wardveil.everkeep.restore-verification.json"

EXPECTED_GATES = {
    "platform-system-acceptance",
    "production-identity-key-custody",
    "cloudflare-runtime-acceptance",
    "everkeep-restore",
    "quarantine-target-readback",
    "observability-monitoring-alerting",
    "security-center-glaze-acceptance",
    "release-provenance-rollback",
    "public-history-safety",
}


def fail(message: str) -> None:
    raise SystemExit(f"Wardveil Seal/Anchor readiness validation failed: {message}")


def main() -> None:
    record = json.loads(RECORD.read_text())
    candidate = json.loads(CANDIDATE.read_text())
    manifest = MANIFEST.read_text()
    runtime = json.loads(RUNTIME.read_text())
    template = json.loads(RUNTIME_TEMPLATE.read_text())
    restore = json.loads(RESTORE.read_text())

    if set(record) != {
        "schema_version", "component", "lifecycle", "next_gate",
        "seal_candidate_declared", "anchor_promotion_authorized", "candidate", "gates",
    }:
        fail("record top-level fields drifted")
    if record["schema_version"] != 2 or record["component"] != "Wardveil Security":
        fail("readiness record identity/schema drifted")
    if record["lifecycle"] != "seal" or record["next_gate"] != "anchor":
        fail("readiness record must describe the current Seal -> Anchor boundary")
    if record["seal_candidate_declared"] is not True:
        fail("Seal lifecycle requires a declared exact candidate")
    if record["anchor_promotion_authorized"] is not False:
        fail("Anchor promotion must remain unauthorized while qualification blockers remain")
    if record["candidate"] != "qualification/seal-candidate.json":
        fail("readiness record must bind the canonical Seal candidate record")

    if candidate.get("schema_version") != 1 or candidate.get("component") != "Wardveil Security":
        fail("candidate identity drifted")
    if candidate.get("candidate_id") != "wardveil-2.0.0-seal.1":
        fail("unexpected Wardveil Seal candidate id")
    if candidate.get("lifecycle") != "seal" or candidate.get("candidate_version") != "2.0.0":
        fail("candidate lifecycle/version drifted")
    source_revision = candidate.get("source_revision")
    if not isinstance(source_revision, str) or not re.fullmatch(r"[0-9a-f]{40}", source_revision):
        fail("candidate source_revision must be an exact commit SHA")
    if candidate.get("production_approved") is not False or candidate.get("authority_effect") != "none":
        fail("Seal candidate must remain non-authorizing before Anchor qualification")
    validations = candidate.get("source_validation")
    if not isinstance(validations, list) or len(validations) < 1 or any(v.get("result") != "success" for v in validations):
        fail("candidate must retain successful exact-source validation evidence")

    if not isinstance(record["gates"], list) or {gate.get("id") for gate in record["gates"]} != EXPECTED_GATES:
        fail("gate inventory drifted")
    for gate in record["gates"]:
        if set(gate) != {"id", "state", "evidence", "reason"}:
            fail(f"{gate.get('id')}: gate fields drifted")
        if gate["state"] not in {"blocked", "passed"}:
            fail(f"{gate['id']}: unsupported state")
        if not gate["evidence"] or not gate["reason"]:
            fail(f"{gate['id']}: evidence and reason are required")

    lifecycle_match = re.search(r"(?m)^lifecycle:\s*([a-z-]+)\s*$", manifest)
    source_match = re.search(r"(?m)^\s{4}source_revision:\s*([0-9a-f]{40})\s*$", manifest)
    next_gate_match = re.search(r"(?m)^\s{2}next_gate:\s*([a-z-]+)\s*$", manifest)
    qualification_match = re.search(r"(?m)^\s{2}qualification_state:\s*([a-z-]+)\s*$", manifest)
    if not lifecycle_match or lifecycle_match.group(1) != "seal":
        fail("manifest lifecycle must be Seal")
    if not source_match or source_match.group(1) != source_revision:
        fail("manifest candidate source revision must match qualification/seal-candidate.json")
    if not next_gate_match or next_gate_match.group(1) != "anchor":
        fail("Seal manifest next_gate must be Anchor")
    if not qualification_match or qualification_match.group(1) not in {"blocked", "in-progress"}:
        fail("Seal qualification must remain blocked or in-progress until Anchor acceptance")

    release_empty = re.search(r"(?m)^\s{2}release:\s*\[\]\s*$", manifest) is not None
    migration_required = len(re.findall(r"(?m)^\s{4}result:\s*applicable-migration-required\s*$", manifest))
    if migration_required != 8:
        fail(f"expected exactly eight external migration-required platform systems, found {migration_required}")
    if runtime.get("production_runtime_status") != "unaccepted":
        fail("runtime acceptance must remain unaccepted until exact deployed evidence passes")
    if template.get("acceptance_status") != "unaccepted":
        fail("production evidence template must remain unaccepted")
    for required in ("health_endpoint", "readiness_endpoint", "restore_verification_exercise"):
        if template.get("checks", {}).get(required, {}).get("status") != "pending":
            fail(f"template {required} must remain pending until real evidence replaces the template")
    if restore.get("provider_repository") != "GoreeCloud/everkeep":
        fail("Everkeep restore consumer must use canonical provider repository")
    if not release_empty:
        fail("published release evidence must not be declared before Anchor qualification")

    blocked = [gate["id"] for gate in record["gates"] if gate["state"] != "passed"]
    if not blocked:
        fail("no Anchor blockers remain; perform a separate exact-candidate Anchor transition instead")

    print(
        "Wardveil Seal candidate guard passed: wardveil-2.0.0-seal.1 is frozen; "
        f"Anchor qualification remains blocked by {len(blocked)} gate groups."
    )


if __name__ == "__main__":
    main()
