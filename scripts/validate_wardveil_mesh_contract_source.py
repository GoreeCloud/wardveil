#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "contracts" / "wardveil.mesh-evidence-profile.json"
MESH_ROOT = ROOT / ".contract-sources" / "goreecloud-mesh"

EXPECTED_PROFILE_VERSION = "1.1.3"
EXPECTED_MESH_REPOSITORY = "GoreeCloud/goreecloud-mesh"
EXPECTED_MESH_REVISION = "1002c74a2f014b04719b6809da22b0026546f8f0"
EXPECTED_WARDVEIL_REPOSITORY = "GoreeCloud/goreecloud-wardveil-security"
EXPECTED_ENVELOPE_VERSION = "goreecloud.evidence-envelope.v1"
EXPECTED_PLATFORM_CONTRACT = "goreecloud.platform-evidence-plane.v1"
EXPECTED_ENVELOPE_REQUIRED = {"version","id","producer","authority_domain","subject","assertion","outcome","source","observed_at","valid_until","data_class","contains_user_content","contains_secret_material"}
EXPECTED_PRODUCER_REQUIRED = {"system","repository","revision","contract"}
REVISION_PATTERN = r"^[0-9a-f]{40}$"
DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"
EXPECTED_RUNTIME_BINDINGS = {
    "trust-evaluation": ("trust_decision", "trust_state"),
    "policy-decision": ("policy_decision", "policy_decision"),
    "protection-result": ("protection_action", "execution_status"),
    "detection-finding": ("detection_finding", "detection_disposition"),
    "scan-finding": ("scan_finding", "scan_result"),
    "quarantine-state": ("quarantine_record", "review_state"),
    "incident-state": ("incident_record", "incident_status"),
    "security-audit-state": ("audit_event", "outcome"),
}
EXPECTED_UNBOUND = {
    "runtime-acceptance": "producer-validity-window-not-established",
    "response-state": "canonical-response-producer-record-not-established",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"Wardveil Mesh source-contract validation failed: {message}")


def load_json(path: Path) -> dict:
    require(path.is_file(), f"missing source contract: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Wardveil Mesh source-contract validation failed: cannot read {path}: {exc}") from exc
    require(isinstance(value, dict), f"source contract is not an object: {path}")
    return value


def contract_path(root: Path, value: object, field: str) -> Path:
    require(isinstance(value, str) and value.strip(), f"{field} is required")
    relative = Path(value)
    require(not relative.is_absolute(), f"{field} must be repository-relative")
    require(".." not in relative.parts, f"{field} must not escape the Mesh checkout")
    require(relative.parts and relative.parts[0] == "contracts", f"{field} must reference Mesh contracts/")
    return root / relative


def validate_producer_bindings(profile: dict) -> None:
    families = profile.get("permitted_assertion_families") or []
    bindings = profile.get("producer_bindings") or {}
    require(isinstance(bindings, dict), "producer_bindings must be an object")
    require(set(bindings) == set(families), "every permitted assertion family must declare one producer-binding status")

    status = bindings.get("security-status") or {}
    require(status.get("status") == "bound", "security-status must remain producer-bound")
    require(status.get("contract") == "contracts/wardveil.status.schema.json", "security-status contract binding drifted")
    require(status.get("record_type") is None and status.get("outcome_field") == "state", "security-status state binding drifted")
    require(status.get("validity_field") == "evidence.valid_until" and status.get("mode") == "dedicated-status-adapter", "security-status validity/mode drifted")

    for assertion, (record_type, outcome_field) in EXPECTED_RUNTIME_BINDINGS.items():
        binding = bindings.get(assertion) or {}
        require(binding.get("status") == "bound", f"{assertion} must remain producer-bound")
        require(binding.get("contract") == "contracts/wardveil.runtime.schema.json", f"{assertion} runtime contract drifted")
        require(binding.get("record_type") == record_type, f"{assertion} record_type binding drifted")
        require(binding.get("outcome_field") == outcome_field, f"{assertion} outcome binding drifted")
        require(binding.get("validity_field") == "valid_until", f"{assertion} validity binding drifted")
        require(binding.get("mode") == "canonical-runtime-record", f"{assertion} binding mode drifted")

    for assertion, reason_code in EXPECTED_UNBOUND.items():
        binding = bindings.get(assertion) or {}
        require(binding.get("status") == "unbound" and binding.get("mode") == "fail-closed", f"{assertion} must remain explicitly fail-closed")
        require(binding.get("reason_code") == reason_code, f"{assertion} fail-closed reason drifted")
        for field in ("contract", "record_type", "outcome_field", "validity_field"):
            require(binding.get(field) is None, f"{assertion} cannot carry partial {field} authority while unbound")

    runtime_acceptance = bindings["runtime-acceptance"]
    related = set(runtime_acceptance.get("related_contracts") or [])
    require("contracts/wardveil.cloudflare.acceptance-evidence.schema.json" in related, "runtime-acceptance must identify its current evidence model")
    require("contracts/wardveil.cloudflare.runtime-acceptance.json" in related, "runtime-acceptance must identify its current acceptance contract")
    acceptance_schema = load_json(ROOT / "contracts/wardveil.cloudflare.acceptance-evidence.schema.json")
    require("valid_until" not in (acceptance_schema.get("properties") or {}), "runtime-acceptance evidence unexpectedly gained valid_until; re-review producer binding instead of preserving this blocker")


def wardveil_rule(schema: dict) -> dict:
    for rule in schema.get("allOf") or []:
        if not isinstance(rule, dict):
            continue
        try:
            producer_system = rule["if"]["properties"]["producer"]["properties"]["system"]
        except (KeyError, TypeError):
            continue
        if isinstance(producer_system, dict) and producer_system.get("const") == "wardveil-security":
            return rule
    raise SystemExit("Wardveil Mesh source-contract validation failed: Mesh envelope lacks the Wardveil producer rule")


def validate_envelope_schema(schema: dict, profile: dict) -> None:
    require(schema.get("type") == "object", "Mesh evidence envelope must be an object")
    require(schema.get("additionalProperties") is False, "Mesh evidence envelope must remain closed")
    require(set(schema.get("required") or []) == EXPECTED_ENVELOPE_REQUIRED, "Mesh evidence required fields drifted")
    properties = schema.get("properties") or {}
    require(isinstance(properties, dict), "Mesh evidence properties are missing")
    require((properties.get("version") or {}).get("const") == EXPECTED_ENVELOPE_VERSION, "Mesh envelope version drifted")
    identifier = properties.get("id") or {}
    require(identifier.get("type") == "string" and identifier.get("minLength") == 1 and identifier.get("maxLength") == 128, "Mesh evidence id contract drifted")
    producer = properties.get("producer") or {}
    require(producer.get("type") == "object" and producer.get("additionalProperties") is False, "Mesh producer identity must remain closed")
    require(set(producer.get("required") or []) == EXPECTED_PRODUCER_REQUIRED, "Mesh producer identity fields drifted")
    producer_properties = producer.get("properties") or {}
    require("wardveil-security" in set((producer_properties.get("system") or {}).get("enum") or []), "Mesh no longer recognizes the Wardveil producer")
    require((producer_properties.get("revision") or {}).get("pattern") == REVISION_PATTERN, "Mesh producer revision must remain an immutable SHA")
    subject = properties.get("subject") or {}
    require(subject.get("type") == "object" and subject.get("additionalProperties") is False, "Mesh subject must remain closed")
    require(set(subject.get("required") or []) == {"kind","id"}, "Mesh subject identity fields drifted")
    subject_properties = subject.get("properties") or {}
    require((subject_properties.get("kind") or {}).get("type") == "string", "Mesh subject kind drifted")
    require((subject_properties.get("id") or {}).get("type") == "string", "Mesh subject id drifted")
    require((subject_properties.get("scope") or {}).get("type") == "string", "Mesh subject scope drifted")
    require((properties.get("assertion") or {}).get("type") == "string", "Mesh assertion must remain producer text")
    require((properties.get("outcome") or {}).get("type") == "string", "Mesh outcome must remain producer text")
    require((properties.get("source") or {}).get("type") == "string", "Mesh source reference must remain text")
    require((properties.get("observed_at") or {}).get("format") == "date-time", "Mesh observed_at format drifted")
    require((properties.get("valid_until") or {}).get("format") == "date-time", "Mesh valid_until format drifted")
    require("derived" in set((properties.get("data_class") or {}).get("enum") or []), "Mesh no longer accepts derived evidence")
    require((properties.get("summary") or {}).get("maxLength") == 512, "Mesh evidence summary bound drifted")
    require((properties.get("payload_digest") or {}).get("pattern") == DIGEST_PATTERN, "Mesh evidence digest contract drifted")
    require((properties.get("contains_user_content") or {}).get("const") is False, "Mesh evidence user-content minimization drifted")
    require((properties.get("contains_secret_material") or {}).get("const") is False, "Mesh evidence secret minimization drifted")
    rule = wardveil_rule(schema)
    then_properties = ((rule.get("then") or {}).get("properties") or {})
    wardveil_producer = ((then_properties.get("producer") or {}).get("properties") or {})
    require((wardveil_producer.get("repository") or {}).get("const") == EXPECTED_WARDVEIL_REPOSITORY, "Mesh Wardveil repository authority drifted")
    require((then_properties.get("authority_domain") or {}).get("const") == "security", "Mesh Wardveil authority domain drifted")
    require((profile.get("mesh_envelope") or {}).get("version") == EXPECTED_ENVELOPE_VERSION, "Wardveil profile envelope version drifted")


def validate_platform_contract(contract: dict, profile: dict) -> None:
    require(contract.get("contract") == EXPECTED_PLATFORM_CONTRACT, "Mesh platform evidence-plane contract drifted")
    require(contract.get("authority") == "coordination-only", "Mesh evidence plane must remain coordination-only")
    require(contract.get("authority_transfer") is False, "Mesh evidence plane cannot transfer producer authority")
    require(contract.get("runtime_acceptance_implied") is False, "Mesh source contract cannot imply runtime acceptance")
    require(contract.get("stable_acceptance_implied") is False, "Mesh source contract cannot imply Stable acceptance")
    envelope_profile = profile.get("mesh_envelope") or {}
    require(contract.get("mesh_envelope") == envelope_profile.get("path"), "Mesh evidence-plane envelope reference drifted")
    transport = contract.get("producer_delivery_transport") or {}
    require(transport.get("https_required_except_loopback") is True, "Mesh delivery must require HTTPS except loopback")
    require(transport.get("redirects_permitted_with_service_identity") is False, "Mesh delivery must not permit service-identity redirects")
    require(transport.get("base_url_user_information_permitted") is False, "Mesh delivery URLs must not contain user information")
    require(transport.get("base_url_query_or_fragment_permitted") is False, "Mesh delivery base URLs must not contain query or fragment components")
    runtime_delivery = profile.get("runtime_delivery") or {}
    require(runtime_delivery.get("producer_service_id") == "wardveil-security", "Wardveil producer service identity drifted")
    require(runtime_delivery.get("write_scope") == "mesh.evidence.write", "Wardveil Mesh write scope drifted")
    require(runtime_delivery.get("read_scope") == "mesh.evidence.read", "Wardveil Mesh read scope drifted")
    require(runtime_delivery.get("producer_identity_must_match_envelope") is True, "Wardveil producer binding weakened")
    require(runtime_delivery.get("https_required_except_loopback") is True, "Wardveil delivery HTTPS requirement weakened")
    require(runtime_delivery.get("production_acceptance") is False, "Wardveil source profile must not claim production delivery acceptance")
    wardveil = next((s for s in contract.get("systems") or [] if isinstance(s, dict) and s.get("system") == "wardveil-security"), None)
    require(wardveil is not None, "Mesh evidence plane no longer declares Wardveil")
    require(wardveil.get("repository") == EXPECTED_WARDVEIL_REPOSITORY, "Mesh evidence-plane Wardveil repository drifted")
    require(wardveil.get("profile") == "contracts/wardveil.mesh-evidence-profile.json", "Mesh Wardveil profile path drifted")
    require(wardveil.get("authority_domains") == ["security"], "Mesh Wardveil authority domains drifted")
    require(contract.get("status") == "development", "Mesh pinned evidence-plane source is no longer Development")
    require(contract.get("production_acceptance") is False, "Mesh pinned evidence-plane source claims production acceptance")


def main() -> None:
    profile = load_json(PROFILE)
    require(profile.get("schema_version") == EXPECTED_PROFILE_VERSION, "unexpected Wardveil Mesh evidence profile version")
    require(profile.get("system") == "wardveil-security", "unexpected Wardveil profile system")
    require(profile.get("producer_repository") == EXPECTED_WARDVEIL_REPOSITORY, "unexpected Wardveil producer repository")
    require(profile.get("authority_domains") == ["security"], "unexpected Wardveil authority domains")
    require(profile.get("production_acceptance") is False, "source profile must not claim production acceptance")
    validate_producer_bindings(profile)

    envelope_profile = profile.get("mesh_envelope") or {}
    platform_profile = profile.get("platform_evidence_plane") or {}
    for name, value in (("mesh_envelope", envelope_profile), ("platform_evidence_plane", platform_profile)):
        require(value.get("repository") == EXPECTED_MESH_REPOSITORY, f"{name} repository drifted")
        require(value.get("revision") == EXPECTED_MESH_REVISION, f"{name} must pin the reviewed Mesh revision")
        require(re.fullmatch(REVISION_PATTERN, str(value.get("revision") or "")) is not None, f"{name} revision is not immutable")
    require(envelope_profile.get("revision") == platform_profile.get("revision"), "Wardveil Mesh contract pins disagree")
    require(platform_profile.get("contract") == EXPECTED_PLATFORM_CONTRACT, "Wardveil platform evidence-plane identity drifted")
    require(platform_profile.get("authority_transfer") is False, "Wardveil profile cannot permit Mesh authority transfer")

    require(MESH_ROOT.is_dir(), "pinned GoreeCloud Mesh source checkout is missing")
    try:
        actual_revision = subprocess.check_output(["git","-C",str(MESH_ROOT),"rev-parse","HEAD"], text=True, stderr=subprocess.STDOUT).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit(f"Wardveil Mesh source-contract validation failed: cannot identify pinned Mesh checkout: {exc}") from exc
    require(actual_revision == EXPECTED_MESH_REVISION, "checked-out Mesh source does not match the reviewed revision")
    envelope_path = contract_path(MESH_ROOT, envelope_profile.get("path"), "mesh_envelope.path")
    platform_path = contract_path(MESH_ROOT, platform_profile.get("path"), "platform_evidence_plane.path")
    validate_envelope_schema(load_json(envelope_path), profile)
    validate_platform_contract(load_json(platform_path), profile)
    print("Wardveil pinned GoreeCloud Mesh source contracts and producer bindings validated at " + EXPECTED_MESH_REVISION + ". Source compatibility only; runtime and production acceptance remain separate.")


if __name__ == "__main__":
    main()
