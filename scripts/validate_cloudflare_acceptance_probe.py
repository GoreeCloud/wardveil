from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "cloudflare" / "acceptance-probe" / "wrangler.jsonc"
SOURCE = ROOT / "cloudflare" / "acceptance-probe" / "src" / "index.ts"
DOC = ROOT / "CLOUDFLARE-ACCEPTANCE-PROBE.md"
RUNTIME = ROOT / "contracts" / "wardveil.cloudflare.runtime-acceptance.json"


def load_jsonc(path: Path):
    text = path.read_text()
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("//"):
            continue
        lines.append(line)
    return json.loads("\n".join(lines))


def require(condition: bool, message: str):
    if not condition:
        raise SystemExit(message)


def main():
    for path in (CONFIG, SOURCE, DOC, RUNTIME):
        require(path.exists(), f"missing required file: {path.relative_to(ROOT)}")

    config = load_jsonc(CONFIG)
    source = SOURCE.read_text()
    doc = DOC.read_text()
    runtime = json.loads(RUNTIME.read_text())

    require(config.get("name") == "goreecloud-wardveil-acceptance-probe", "unexpected probe worker name")
    require(config.get("workers_dev") is False, "acceptance probe must disable workers_dev")
    require(config.get("preview_urls") is False, "acceptance probe must disable preview URLs")

    services = config.get("services", [])
    require(len(services) == 1, "acceptance probe must declare exactly one service binding")
    service = services[0]
    require(service.get("binding") == "WARDVEIL_PERSISTENCE_SERVICE", "unexpected persistence service binding")
    require(service.get("service") == "goreecloud-wardveil-persistence", "acceptance probe must bind canonical persistence worker")

    variables = config.get("vars", {})
    require(variables.get("EXPECTED_REVISION") == "UNSET_AT_DEPLOYMENT", "source config must not bake in a production revision")
    require(variables.get("ACCEPTANCE_TENANT") == "wardveil-runtime-acceptance", "unexpected acceptance tenant")

    required_source_tokens = [
        "runAcceptance(expectedRevision",
        "revision_mismatch",
        "authorized_append_read",
        "duplicate_record_rejection",
        "checkpoint_non_regression",
        "payload_digest_verification",
        "pitr_availability",
        'return new Response("Not Found", { status: 404 })',
        'status: anyFailed ? "degraded" : "unaccepted"',
        'security_state_authority: false',
        'protection_claim_authority: false',
        'everkeep_recovery_authority_preserved: true',
    ]
    for token in required_source_tokens:
        require(token in source, f"acceptance probe missing invariant: {token}")

    required_doc_tokens = [
        "service binding",
        "cannot set production status to `accepted` by itself",
        "Storage health is not Wardveil protection",
        "PITR availability is not restore verification",
        "Everkeep retains resilience and recovery authority",
        "public mutation or generic public acceptance endpoint must not be created",
    ]
    for token in required_doc_tokens:
        require(token in doc, f"acceptance probe documentation missing invariant: {token}")

    runtime_requirements = set(runtime.get("required_acceptance_evidence", []))
    probe_covered = {
        "authorized_append_read",
        "duplicate_record_rejection",
        "checkpoint_non_regression",
        "payload_digest_verification",
        "pitr_availability",
    }
    probe_external = {
        "deployed_revision_match",
        "health_endpoint",
        "retention_alarm_evidence",
        "restore_verification_exercise",
        "observability_failure_evidence",
        "public_mutation_surface_absent",
    }
    require(probe_covered | probe_external == runtime_requirements, "probe evidence partition must exactly match runtime acceptance requirements")
    require(not (probe_covered & probe_external), "probe evidence partition must be disjoint")

    require('"accepted"' not in source.split('status: "unaccepted" | "degraded";')[0], "probe result type must not admit accepted status")
    print("Wardveil Cloudflare acceptance probe validation passed")


if __name__ == "__main__":
    main()
