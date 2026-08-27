#!/usr/bin/env python3
"""Validate the Cloudflare Wardveil authorization-issuer source candidate."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "cloudflare" / "authorization-issuer"
CONFIG = BASE / "wrangler.jsonc"
SOURCE = BASE / "src" / "index.ts"
PACKAGE = BASE / "package.json"
TSCONFIG = BASE / "tsconfig.json"
CONTRACT = ROOT / "contracts" / "wardveil.service-identity.json"
DOC = ROOT / "SERVICE-IDENTITY.md"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"Wardveil Cloudflare authorization issuer validation failed: {message}")


def main() -> None:
    for path in (CONFIG, SOURCE, PACKAGE, TSCONFIG, CONTRACT, DOC):
        require(path.is_file(), f"missing required file: {path.relative_to(ROOT)}")

    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    source = SOURCE.read_text(encoding="utf-8")
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    docs = DOC.read_text(encoding="utf-8").lower()

    require(config.get("name") == "goreecloud-wardveil-authorization-issuer", "unexpected Worker name")
    require(config.get("main") == "src/index.ts", "unexpected Worker entrypoint")
    required_secrets = ((config.get("secrets") or {}).get("required") or [])
    require(required_secrets == ["WARDVEIL_AUTH_SIGNING_KEY"], "signing secret must be a required encrypted binding")
    vars_ = config.get("vars") or {}
    require(vars_.get("WARDVEIL_AUTH_ISSUER_ID") == "wardveil-policy-runtime", "issuer identity metadata missing")
    require(vars_.get("WARDVEIL_AUTH_EXECUTOR_ID") == "wardveil-protect-executor-runtime", "executor identity metadata missing")
    require(vars_.get("WARDVEIL_AUTH_SIGNING_KEY_ID") == "wardveil-auth-current", "signing key ID metadata missing")
    require("WARDVEIL_AUTH_SIGNING_KEY" not in vars_, "signing key must not be a plaintext var")

    for forbidden in (
        "private_key", "access_token", "refresh_token", "session_token",
        "client_secret", "authorization_header", "cookie", "secret_value",
    ):
        require(forbidden not in CONFIG.read_text(encoding="utf-8").lower(), f"Wrangler config contains forbidden secret-bearing field: {forbidden}")

    for token in (
        'const SIGNATURE_ALGORITHM = "HMAC-SHA256-reference-only"',
        "class WardveilAuthorizationIssuer extends WorkerEntrypoint<Bindings>",
        "async signExecutionAuthorization(request: SignRequest)",
        'url.pathname !== "/healthz"',
        'production_runtime_status: "unaccepted"',
        "authorization.signing_key_id !== env.WARDVEIL_AUTH_SIGNING_KEY_ID",
        "authorization.executor_id !== env.WARDVEIL_AUTH_EXECUTOR_ID",
        "authorization.issuer_id !== env.WARDVEIL_AUTH_ISSUER_ID",
        "policy_digest_mismatch",
        "authorization_outlives_policy",
        "crypto.subtle.importKey",
        "crypto.subtle.sign",
    ):
        require(token in source, f"source missing required boundary: {token}")

    require('url.pathname === "/sign"' not in source, "public signing route must not exist")
    require('url.pathname === "/authorize"' not in source, "public authorization route must not exist")
    require("request.json" not in source, "public HTTP request body must not drive signing")
    require("this.env.WARDVEIL_AUTH_SIGNING_KEY," in source, "RPC signer must consume encrypted secret binding")
    require("WARDVEIL_AUTH_SIGNING_KEY" not in source.split("return Response.json", 1)[-1].split("});", 1)[0], "health response must not expose signing key binding")

    cloudflare = contract.get("cloudflare_candidate") or {}
    require(cloudflare.get("secret_value_in_wrangler_configuration_allowed") is False, "contract must prohibit secret values in Wrangler")
    require(cloudflare.get("secret_value_in_git_allowed") is False, "contract must prohibit secret values in Git")
    require(cloudflare.get("service_binding_or_equivalent_authenticated_channel_required_for_internal_authorization_operations") is True, "internal signing transport must be authenticated")
    require((contract.get("production_acceptance") or {}).get("status") == "unaccepted", "candidate must remain production-unaccepted")

    for phrase in (
        "internal authorization-issuer worker",
        "encrypted secret binding",
        "no production secret is created or stored by this source milestone",
    ):
        require(phrase in docs, f"documentation missing Cloudflare boundary: {phrase}")

    print("Wardveil Cloudflare authorization issuer candidate validation passed.")


if __name__ == "__main__":
    main()
