#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "cloudflare" / "quarantine-executor"
WRANGLER = BASE / "wrangler.jsonc"
SOURCE = BASE / "src" / "index.ts"
PACKAGE = BASE / "package.json"
TSCONFIG = BASE / "tsconfig.json"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def jsonc(path: Path) -> dict:
    text = path.read_text()
    lines = [line for line in text.splitlines() if not line.lstrip().startswith("//")]
    return json.loads("\n".join(lines))


def main() -> None:
    for path in (WRANGLER, SOURCE, PACKAGE, TSCONFIG):
        require(path.is_file(), f"missing Cloudflare quarantine executor file: {path.relative_to(ROOT)}")

    config = jsonc(WRANGLER)
    source = SOURCE.read_text()
    package = json.loads(PACKAGE.read_text())

    require(config.get("name") == "goreecloud-wardveil-quarantine-executor", "unexpected quarantine executor Worker name")
    require(config.get("workers_dev") is False, "quarantine executor workers_dev must remain disabled")
    require(config.get("preview_urls") is False, "quarantine executor preview URLs must remain disabled")
    require(not config.get("routes"), "quarantine executor must not define public routes")

    variables = config.get("vars") or {}
    require(variables.get("WARDVEIL_AUTH_ISSUER_ID") == "wardveil-policy-runtime", "unexpected authorization issuer identity")
    require(variables.get("WARDVEIL_AUTH_EXECUTOR_ID") == "wardveil-quarantine-executor-runtime", "unexpected quarantine executor identity")
    require(variables.get("WARDVEIL_AUTH_SIGNING_KEY_ID") == "wardveil-auth-current", "unexpected signing key identity")
    require(variables.get("WARDVEIL_PRODUCTION_RUNTIME_STATUS") == "unaccepted", "source candidate must remain runtime-unaccepted")
    require(variables.get("WARDVEIL_QUARANTINE_TARGET_SERVICE") == "REPLACE_AT_DEPLOYMENT", "target service must remain explicit source placeholder")
    require(set((variables.get("WARDVEIL_QUARANTINE_RESOURCE_TYPES") or "").split(",")) == {"mail_attachment", "drive_file", "browser_download", "ai_artifact"}, "unexpected quarantine resource-type boundary")

    services = {item.get("binding"): item.get("service") for item in config.get("services") or []}
    require(services.get("WARDVEIL_PERSISTENCE_SERVICE") == "goreecloud-wardveil-persistence", "missing canonical persistence service binding")
    require(services.get("WARDVEIL_QUARANTINE_TARGET") == "REPLACE_AT_DEPLOYMENT", "quarantine target service binding must remain explicit placeholder")

    secrets = (config.get("secrets") or {}).get("required") or []
    require(secrets == ["WARDVEIL_AUTH_VERIFICATION_KEY"], "unexpected quarantine executor secret contract")
    require("WARDVEIL_AUTH_VERIFICATION_KEY" not in variables, "verification key must not be a plaintext Wrangler var")

    for token in (
        "executeQuarantine",
        "claimExecutionAuthorization",
        "applyQuarantine",
        "readQuarantine",
        "finalizeExecutionAuthorization",
        "authorization_provenance",
        "execution_reconciliation_required",
        "target_quarantine_readback_unverified",
        "source_candidate_must_remain_unaccepted",
        "quarantine_target_not_configured",
        "function parseTime(value: unknown, reason: string)",
        "value !== value.trim()",
        "/(?:Z|[+-]\\d{2}:\\d{2})$/",
    ):
        require(token in source, f"missing Cloudflare quarantine executor invariant: {token}")

    claim_index = source.index("claimExecutionAuthorization")
    target_index = source.index("applyQuarantine", claim_index)
    finalize_index = source.index("finalizeExecutionAuthorization", target_index)
    require(claim_index < target_index < finalize_index, "execution sequence must remain claim -> target -> receipt")
    require("async fetch(_request: Request): Promise<Response>" in source, "missing explicit non-public fetch boundary")
    require('return new Response("Not Found", { status: 404 });' in source, "public fetch must remain 404-only")
    require("/execute" not in source and 'pathname' not in source, "generic public execution routing must remain absent")

    serialized = (WRANGLER.read_text() + SOURCE.read_text()).lower()
    for forbidden in ("private_key", "access_token", "refresh_token", "session_token", "authorization: bearer", "password="):
        require(forbidden not in serialized, f"potential secret material found in quarantine executor source: {forbidden}")

    require(package.get("devDependencies", {}).get("typescript") == "5.9.2", "quarantine executor TypeScript must remain pinned")
    require(package.get("devDependencies", {}).get("@cloudflare/workers-types") == "5.20260827.1", "Workers types must remain pinned")
    require(package.get("devDependencies", {}).get("wrangler") == "4.37.0", "Wrangler must remain pinned")

    print("Cloudflare quarantine executor candidate validation passed")


if __name__ == "__main__":
    main()
