import { WorkerEntrypoint } from "cloudflare:workers";

const AUTHORIZATION_VERSION = "0.1.0";
const SIGNATURE_ALGORITHM = "HMAC-SHA256-reference-only";
const MAX_AUTHORIZATION_TTL_MS = 5 * 60 * 1000;
const CLOCK_SKEW_MS = 30 * 1000;
const POLICY_ACTIONS = new Set([
  "allow", "allow_and_log", "warn", "step_up", "restrict",
  "quarantine", "revoke", "block", "isolate", "escalate",
]);

type Scope = {
  resource_type: string;
  resource_id: string;
  [key: string]: unknown;
};

type WardveilPolicyRecord = {
  contract_version: "0.1.0";
  record_type: "policy_decision";
  record_id: string;
  correlation_id: string;
  producer: { id: string; authoritative: boolean };
  scope: Scope;
  observed_at: string;
  valid_until: string;
  policy_decision: string;
  [key: string]: unknown;
};

type AuthorizationSigningMaterial = {
  authorization_version: "0.1.0";
  authorization_id: string;
  issuer_id: string;
  policy_record_id: string;
  correlation_id: string;
  executor_id: string;
  action: string;
  scope: Scope;
  idempotency_key: string;
  nonce: string;
  issued_at: string;
  expires_at: string;
  policy_digest_sha256: string;
  signing_key_id: string;
};

type SignRequest = {
  policy_record: WardveilPolicyRecord;
  authorization: AuthorizationSigningMaterial;
};

type SignResponse = {
  signing_key_id: string;
  signature_algorithm: typeof SIGNATURE_ALGORITHM;
  signature: string;
};

type Bindings = {
  WARDVEIL_AUTH_SIGNING_KEY: string;
  WARDVEIL_AUTH_SIGNING_KEY_ID: string;
  WARDVEIL_AUTH_ISSUER_ID: string;
  WARDVEIL_AUTH_EXECUTOR_ID: string;
};

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    const object = value as Record<string, unknown>;
    return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${canonical(object[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function hmacSha256Hex(keyValue: string, value: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(keyValue),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value));
  return [...new Uint8Array(signature)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function requireString(value: unknown, reason: string, max = 256): asserts value is string {
  if (typeof value !== "string" || !value || value.length > max) throw new Error(reason);
}

function parseTime(value: string, reason: string): number {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) throw new Error(reason);
  return parsed;
}

function requirePolicy(record: WardveilPolicyRecord, env: Bindings): void {
  if (!record || typeof record !== "object") throw new Error("invalid_policy_record");
  if (record.contract_version !== "0.1.0" || record.record_type !== "policy_decision") throw new Error("invalid_policy_record");
  requireString(record.record_id, "invalid_policy_record");
  requireString(record.correlation_id, "invalid_policy_record");
  requireString(record.producer?.id, "invalid_policy_producer");
  if (record.producer.authoritative !== true || record.producer.id !== env.WARDVEIL_AUTH_ISSUER_ID) {
    throw new Error("unauthorized_policy_issuer");
  }
  requireString(record.scope?.resource_type, "invalid_policy_scope");
  requireString(record.scope?.resource_id, "invalid_policy_scope");
  if (!POLICY_ACTIONS.has(record.policy_decision)) throw new Error("unsupported_policy_action");
  const validUntil = parseTime(record.valid_until, "invalid_policy_validity");
  if (validUntil <= Date.now()) throw new Error("expired_policy_record");
}

async function requireAuthorizationBinding(
  request: SignRequest,
  env: Bindings,
): Promise<void> {
  const record = request.policy_record;
  const authorization = request.authorization;
  requirePolicy(record, env);
  if (!authorization || typeof authorization !== "object") throw new Error("invalid_execution_authorization");
  if (authorization.authorization_version !== AUTHORIZATION_VERSION) throw new Error("unsupported_authorization_version");
  for (const [value, reason] of [
    [authorization.authorization_id, "missing_authorization_id"],
    [authorization.policy_record_id, "missing_policy_record_id"],
    [authorization.correlation_id, "missing_correlation_id"],
    [authorization.executor_id, "missing_executor_id"],
    [authorization.action, "missing_action"],
    [authorization.idempotency_key, "missing_idempotency_key"],
    [authorization.nonce, "missing_nonce"],
    [authorization.policy_digest_sha256, "missing_policy_digest"],
    [authorization.signing_key_id, "missing_signing_key_id"],
  ] as const) {
    requireString(value, reason);
  }
  requireString(authorization.scope?.resource_type, "invalid_authorization_scope");
  requireString(authorization.scope?.resource_id, "invalid_authorization_scope");
  if (authorization.issuer_id !== env.WARDVEIL_AUTH_ISSUER_ID) throw new Error("issuer_identity_mismatch");
  if (authorization.executor_id !== env.WARDVEIL_AUTH_EXECUTOR_ID) throw new Error("executor_identity_mismatch");
  if (authorization.signing_key_id !== env.WARDVEIL_AUTH_SIGNING_KEY_ID) throw new Error("signing_key_id_mismatch");
  if (authorization.policy_record_id !== record.record_id) throw new Error("policy_record_binding_mismatch");
  if (authorization.correlation_id !== record.correlation_id) throw new Error("correlation_binding_mismatch");
  if (authorization.action !== record.policy_decision) throw new Error("action_binding_mismatch");
  if (canonical(authorization.scope) !== canonical(record.scope)) throw new Error("scope_binding_mismatch");
  const expectedDigest = await sha256Hex(canonical(record));
  if (authorization.policy_digest_sha256 !== expectedDigest) throw new Error("policy_digest_mismatch");

  const issuedAt = parseTime(authorization.issued_at, "invalid_authorization_time");
  const expiresAt = parseTime(authorization.expires_at, "invalid_authorization_time");
  const policyValidUntil = parseTime(record.valid_until, "invalid_policy_validity");
  const now = Date.now();
  if (issuedAt > now + CLOCK_SKEW_MS) throw new Error("future_dated_authorization");
  if (expiresAt <= now) throw new Error("expired_authorization");
  if (expiresAt <= issuedAt || expiresAt - issuedAt > MAX_AUTHORIZATION_TTL_MS) {
    throw new Error("invalid_authorization_validity_window");
  }
  if (expiresAt > policyValidUntil) throw new Error("authorization_outlives_policy");
}

export default class WardveilAuthorizationIssuer extends WorkerEntrypoint<Bindings> {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (request.method !== "GET") return new Response("Method Not Allowed", { status: 405 });
    if (url.pathname !== "/healthz") return new Response("Not Found", { status: 404 });
    return Response.json({
      status: "ok",
      component: "wardveil-authorization-issuer-source-candidate",
      authorization_version: AUTHORIZATION_VERSION,
      production_runtime_status: "unaccepted",
    });
  }

  async signExecutionAuthorization(request: SignRequest): Promise<SignResponse> {
    if (!this.env.WARDVEIL_AUTH_SIGNING_KEY) throw new Error("signing_key_unavailable");
    await requireAuthorizationBinding(request, this.env);
    const signature = await hmacSha256Hex(
      this.env.WARDVEIL_AUTH_SIGNING_KEY,
      canonical(request.authorization),
    );
    return {
      signing_key_id: this.env.WARDVEIL_AUTH_SIGNING_KEY_ID,
      signature_algorithm: SIGNATURE_ALGORITHM,
      signature,
    };
  }
}
