#!/usr/bin/env python3
"""Fail closed if Wardveil lifecycle promotion outruns release-critical evidence."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RECORD = ROOT / "qualification" / "seal-readiness.json"
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
}


def fail(message: str) -> None:
    raise SystemExit(f"Wardveil Seal readiness validation failed: {message}")


def main() -> None:
    record = json.loads(RECORD.read_text())
    manifest = MANIFEST.read_text()
    runtime = json.loads(RUNTIME.read_text())
    template = json.loads(RUNTIME_TEMPLATE.read_text())
    restore = json.loads(RESTORE.read_text())

    if set(record) != {
        "schema_version", "component", "lifecycle", "next_gate",
        "seal_candidate_declared", "promotion_authorized", "gates",
    }:
        fail("record top-level fields drifted")
    if record["schema_version"] != 1 or record["component"] != "Wardveil Security":
        fail("record identity drifted")
    if not isinstance(record["gates"], list) or {
        gate.get("id") for gate in record["gates"]
    } != EXPECTED_GATES:
        fail("gate inventory drifted")
    for gate in record["gates"]:
        if set(gate) != {"id", "state", "evidence", "reason"}:
            fail(f"{gate.get('id')}: gate fields drifted")
        if gate["state"] not in {"blocked", "passed"}:
            fail(f"{gate['id']}: unsupported state")
        if not gate["evidence"] or not gate["reason"]:
            fail(f"{gate['id']}: evidence and reason are required")

    lifecycle_match = re.search(r"(?m)^lifecycle:\s*([a-z-]+)\s*$", manifest)
    if not lifecycle_match:
        fail("manifest lifecycle is unreadable")
    lifecycle = lifecycle_match.group(1)
    candidate_null = re.search(r"(?m)^\s{2}candidate_identity:\s*null\s*$", manifest) is not None
    release_empty = re.search(r"(?m)^\s{2}release:\s*\[\]\s*$", manifest) is not None
    migration_required = len(re.findall(r"(?m)^\s{4}result:\s*applicable-migration-required\s*$", manifest))

    blocked = [gate["id"] for gate in record["gates"] if gate["state"] != "passed"]
    if record["promotion_authorized"] is not False or record["seal_candidate_declared"] is not False:
        fail("current blocked Weave record must not authorize or declare a Seal candidate")
    if record["lifecycle"] != "weave" or record["next_gate"] != "seal":
        fail("readiness record must describe current Weave -> Seal boundary")
    if lifecycle != "weave" or not candidate_null:
        fail("manifest must remain Weave with candidate_identity null while readiness is blocked")
    if migration_required != 8:
        fail(f"expected exactly eight external migration-required platform systems, found {migration_required}")
    if runtime.get("production_runtime_status") != "unaccepted":
        fail("current runtime contract must remain unaccepted until full exact-deployment evidence passes")
    if template.get("acceptance_status") != "unaccepted":
        fail("production evidence template must remain unaccepted")
    for required in ("health_endpoint", "readiness_endpoint", "restore_verification_exercise"):
        if template.get("checks", {}).get(required, {}).get("status") != "pending":
            fail(f"template {required} must remain pending until real evidence replaces the template")
    if restore.get("provider_repository") != "GoreeCloud/everkeep":
        fail("Everkeep restore consumer must use canonical provider repository")
    if not release_empty:
        fail("no release evidence may be declared while the current Seal-readiness record is blocked")
    if not blocked:
        fail("current record unexpectedly has no blockers; a separate exact-candidate transition is required")

    if lifecycle in {"seal", "anchor"}:
        fail("promotion is prohibited while this readiness record remains blocked")

    print("Wardveil Seal readiness guard passed: Weave remains fail-closed with 8 blocked release-critical gates.")


if __name__ == "__main__":
    main()
