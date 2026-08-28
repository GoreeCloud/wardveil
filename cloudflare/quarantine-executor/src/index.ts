import { WorkerEntrypoint } from "cloudflare:workers";

const AUTHORIZATION_VERSION = "0.1.0";
const SIGNATURE_ALGORITHM = "HMAC-SHA256-reference-only";
const MAX_AUTHORIZATION_TTL_MS = 5 * 60 * 1000;
const CLOCK_SKEW_MS = 30 * 1000;
const TARGET_DEPLOYMENT_PLACEHOLDER = "REPLACE_AT_DEPLOYMENT";

type Scope = {
  resource_type: string;
  resource_id: string;
  operation?: string;
  principal_class?: string;
};

type PolicyRecord = {
  contract_version: "0.1.0";
  record_type: "policy_decision";
  record_id: string;
  correlation_id: string;
  producer: { id: string; authoritative: boolean };
  scope: Scope;
  observed_at: string;
  valid_until: string;
  evidence_refs?: string[];
  policy_decision: string;
};

type ExecutionAuthorization = {
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
  signature_algorithm: string;
  signature: string;
};

type ExecutionClaim = {
  authorization_id: string;
  authorization_digest_sha256: string;
  correlation_id: string;
  executor_id: string;
  action: string;
  scope: Scope;
  idempotency_key: string;
  nonce: string;
  issued_at: string;
  expires_at: string;
};

type WardveilRecord = {
  record_id: string;
  record_type: string;
  correlation_id: string;
  observed_at: string;
  producer: { id: string; authoritative: boolean };
  scope: Scope;
  evidence_refs: string[];
  [key: string]: unknown;
};

type ExecutionReceipt = {
  receipt_id: string;
  outcome: string;
  protection_record: WardveilRecord;
  [key: string]: unknown;
};

type PersistenceService = {
  claimExecutionAuthorization(tenantId: string, claim: ExecutionClaim): Promise<{
    status: "new" | "execution_reconciliation_required" | "idempotent_finalized";
    receipt?: ExecutionReceipt;
  }>;
  finalizeExecutionAuthorization(
    tenantId: string,
    claim: ExecutionClaim,
    protectionRecord: WardveilRecord,
  ): Promise<ExecutionReceipt>;
  append(tenantId: string, record: WardveilRecord, retentionClass?: string): Promise<unknown>;
};

type TargetApplyResult = {
  status: "applied" | "already_applied" | "failed" | "unknown";
  operation_id: string;
  state_ref: string;
  evidence_ref: string;
  reason: string;
};

type TargetReadback = {
  status: "quarantined" | "not_quarantined" | "unknown";
  operation_id: string;
  state_ref: string;
  evidence_ref: string;
};

type QuarantineTargetService = {
  applyQuarantine(request: {
    operation_id: string;
    correlation_id: string;
    scope: Scope;
  }): Promise<TargetApplyResult>;
  readQuarantine(request: { scope: Scope }): Promise<TargetReadback | null>;
};

type Bindings = {
  WARDVEIL_PERSISTENCE_SERVICE: PersistenceService;
  WARDVEIL_QUARANTINE_TARGET: QuarantineTargetService;
  WARDVEIL_AUTH_VERIFICATION_KEY: string;
  WARDVEIL_AUTH_ISSUER_ID: string;
  WARDVEIL_AUTH_EXECUTOR_ID: string;
  WARDVEIL_AUTH_SIGNING_KEY_ID: string;
  WARDVEIL_QUARANTINE_RESOURCE_TYPES: string;
  WARDVEIL_QUARANTINE_TARGET_SERVICE: string;
  WARDVEIL_PRODUCTION_RUNTIME_STATUS: string;
};

type ExecuteRequest = {
  tenant_id: string;
  policy_record: PolicyRecord;
  authorization: ExecutionAuthorization;
  reason: string;
};

type ExecuteResponse = {
  accepted: boolean;
  reason: string;
  reconciliation_required?: boolean;
  idempotent_replay?: boolean;
  receipt?: ExecutionReceipt;
  protection_record?: WardveilRecord;
  quarantine_record?: WardveilRecord;
  audit_record?: WardveilRecord;
  evidence_persistence_degraded?: boolean;
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

function fromHex(value: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/.test(value)) throw new Error("invalid_authorization_signature");
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < value.length; index += 2) {
    bytes[index / 2] = Number.parseInt(value.slice(index, index + 2), 16);
  }
  return bytes;
}

async function verifyHmac(keyValue: string, material: unknown, signatureHex: string): Promise<boolean> {
  if (!keyValue) throw new Error("verification_key_unavailable");
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(keyValue),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"],
  );
  return crypto.subtle.verify(
    "HMAC",
    key,
    fromHex(signatureHex),
    new TextEncoder().encode(canonical(material)),
  );
}

function requireString(value: unknown, reason: string, max = 256): asserts value is string {
  if (typeof value !== "string" || !value || value.length > max) throw new Error(reason);
}

function parseTime(value: string, reason: string): number {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) throw new Error(reason);
  return parsed;
}

function signingMaterial(authorization: ExecutionAuthorization): Record<string, unknown> {
  return {
    authorization_version: authorization.authorization_version,
    authorization_id: authorization.authorization_id,
    issuer_id: authorization.issuer_id,
    policy_record_id: authorization.policy_record_id,
    correlation_id: authorization.correlation_id,
    executor_id: authorization.executor_id,
    action: authorization.action,
    scope: authorization.scope,
    idempotency_key: authorization.idempotency_key,
    nonce: authorization.nonce,
    issued_at: authorization.issued_at,
    expires_at: authorization.expires_at,
    policy_digest_sha256: authorization.policy_digest_sha256,
    signing_key_id: authorization.signing_key_id,
  };
}

async function verifyRequest(request: ExecuteRequest, env: Bindings): Promise<void> {
  requireString(request.tenant_id, "invalid_tenant_id", 128);
  requireString(request.reason, "bounded_quarantine_reason_required", 256);
  if (env.WARDVEIL_PRODUCTION_RUNTIME_STATUS !== "unaccepted") throw new Error("source_candidate_must_remain_unaccepted");
  if (env.WARDVEIL_QUARANTINE_TARGET_SERVICE === TARGET_DEPLOYMENT_PLACEHOLDER) {
    throw new Error("quarantine_target_not_configured");
  }

  const record = request.policy_record;
  const authorization = request.authorization;
  if (!record || record.contract_version !== "0.1.0" || record.record_type !== "policy_decision") {
    throw new Error("invalid_policy_record");
  }
  requireString(record.record_id, "invalid_policy_record");
  requireString(record.correlation_id, "invalid_policy_record");
  requireString(record.producer?.id, "invalid_policy_producer");
  if (record.producer.authoritative !== true || record.producer.id !== env.WARDVEIL_AUTH_ISSUER_ID) {
    throw new Error("unauthorized_policy_issuer");
  }
  requireString(record.scope?.resource_type, "invalid_policy_scope");
  requireString(record.scope?.resource_id, "invalid_policy_scope");
  if (record.policy_decision !== "quarantine") throw new Error("quarantine_action_required");

  const allowedResourceTypes = new Set(
    env.WARDVEIL_QUARANTINE_RESOURCE_TYPES.split(",").map((value) => value.trim()).filter(Boolean),
  );
  if (!allowedResourceTypes.has(record.scope.resource_type)) throw new Error("executor_resource_type_not_authorized");

  if (!authorization || authorization.authorization_version !== AUTHORIZATION_VERSION) {
    throw new Error("invalid_execution_authorization");
  }
  if (authorization.signature_algorithm !== SIGNATURE_ALGORITHM) throw new Error("unsupported_signature_algorithm");
  for (const [value, reason] of [
    [authorization.authorization_id, "missing_authorization_id"],
    [authorization.issuer_id, "missing_issuer_id"],
    [authorization.policy_record_id, "missing_policy_record_id"],
    [authorization.correlation_id, "missing_correlation_id"],
    [authorization.executor_id, "missing_executor_id"],
    [authorization.action, "missing_action"],
    [authorization.idempotency_key, "missing_idempotency_key"],
    [authorization.nonce, "missing_nonce"],
    [authorization.policy_digest_sha256, "missing_policy_digest"],
    [authorization.signing_key_id, "missing_signing_key_id"],
    [authorization.signature, "missing_signature"],
  ] as const) requireString(value, reason);

  if (authorization.issuer_id !== env.WARDVEIL_AUTH_ISSUER_ID) throw new Error("issuer_identity_mismatch");
  if (authorization.executor_id !== env.WARDVEIL_AUTH_EXECUTOR_ID) throw new Error("executor_identity_mismatch");
  if (authorization.signing_key_id !== env.WARDVEIL_AUTH_SIGNING_KEY_ID) throw new Error("signing_key_id_mismatch");
  if (authorization.action !== "quarantine") throw new Error("quarantine_action_required");
  if (authorization.policy_record_id !== record.record_id) throw new Error("policy_record_binding_mismatch");
  if (authorization.correlation_id !== record.correlation_id) throw new Error("correlation_binding_mismatch");
  if (canonical(authorization.scope) !== canonical(record.scope)) throw new Error("scope_binding_mismatch");

  const expectedPolicyDigest = await sha256Hex(canonical(record));
  if (authorization.policy_digest_sha256 !== expectedPolicyDigest) throw new Error("policy_digest_mismatch");
  const issuedAt = parseTime(authorization.issued_at, "invalid_authorization_time");
  const expiresAt = parseTime(authorization.expires_at, "invalid_authorization_time");
  const policyValidUntil = parseTime(record.valid_until, "invalid_policy_validity");
  const now = Date.now();
  if (policyValidUntil <= now) throw new Error("expired_policy_record");
  if (issuedAt > now + CLOCK_SKEW_MS) throw new Error("future_dated_authorization");
  if (expiresAt <= now) throw new Error("expired_authorization");
  if (expiresAt <= issuedAt || expiresAt - issuedAt > MAX_AUTHORIZATION_TTL_MS) {
    throw new Error("invalid_authorization_validity_window");
  }
  if (expiresAt > policyValidUntil) throw new Error("authorization_outlives_policy");

  if (!await verifyHmac(env.WARDVEIL_AUTH_VERIFICATION_KEY, signingMaterial(authorization), authorization.signature)) {
    throw new Error("invalid_authorization_signature");
  }
}

function uniqueRefs(refs: Array<string | undefined>): string[] {
  return [...new Set(refs.filter((value): value is string => typeof value === "string" && value.length > 0))];
}

export default class WardveilQuarantineExecutor extends WorkerEntrypoint<Bindings> {
  async fetch(_request: Request): Promise<Response> {
    return new Response("Not Found", { status: 404 });
  }

  async executeQuarantine(request: ExecuteRequest): Promise<ExecuteResponse> {
    try {
      await verifyRequest(request, this.env);
    } catch (error) {
      return { accepted: false, reason: error instanceof Error ? error.message : "request_verification_failed" };
    }

    const authorization = request.authorization;
    const policy = request.policy_record;
    const authDigest = await sha256Hex(canonical(authorization));
    const claim: ExecutionClaim = {
      authorization_id: authorization.authorization_id,
      authorization_digest_sha256: authDigest,
      correlation_id: authorization.correlation_id,
      executor_id: authorization.executor_id,
      action: authorization.action,
      scope: authorization.scope,
      idempotency_key: authorization.idempotency_key,
      nonce: authorization.nonce,
      issued_at: authorization.issued_at,
      expires_at: authorization.expires_at,
    };

    let claimDecision: Awaited<ReturnType<PersistenceService["claimExecutionAuthorization"]>>;
    try {
      claimDecision = await this.env.WARDVEIL_PERSISTENCE_SERVICE.claimExecutionAuthorization(request.tenant_id, claim);
    } catch (error) {
      return { accepted: false, reason: error instanceof Error ? error.message : "execution_claim_failed" };
    }
    if (claimDecision.status === "idempotent_finalized" && claimDecision.receipt) {
      return {
        accepted: true,
        reason: "idempotent_finalized_execution",
        idempotent_replay: true,
        receipt: claimDecision.receipt,
        protection_record: claimDecision.receipt.protection_record,
      };
    }
    if (claimDecision.status === "execution_reconciliation_required") {
      return { accepted: false, reason: claimDecision.status, reconciliation_required: true };
    }

    const operationId = `wardveil-quarantine-${authDigest.slice(0, 32)}`;
    let targetResult: TargetApplyResult;
    try {
      targetResult = await this.env.WARDVEIL_QUARANTINE_TARGET.applyQuarantine({
        operation_id: operationId,
        correlation_id: authorization.correlation_id,
        scope: authorization.scope,
      });
    } catch (_error) {
      return { accepted: false, reason: "target_quarantine_outcome_unknown", reconciliation_required: true };
    }

    const evidenceRefs = uniqueRefs([...(policy.evidence_refs ?? []), targetResult.evidence_ref]);
    const observedAt = new Date().toISOString();
    let executionStatus: "succeeded" | "failed";
    let reasonCode: string;
    let targetStateRef = targetResult.state_ref;

    if (targetResult.status === "unknown") {
      return { accepted: false, reason: "target_quarantine_outcome_unknown", reconciliation_required: true };
    }
    if (targetResult.status === "failed") {
      executionStatus = "failed";
      reasonCode = targetResult.reason || "target_quarantine_failed";
    } else {
      let readback: TargetReadback | null;
      try {
        readback = await this.env.WARDVEIL_QUARANTINE_TARGET.readQuarantine({ scope: authorization.scope });
      } catch (_error) {
        return { accepted: false, reason: "target_quarantine_readback_unverified", reconciliation_required: true };
      }
      if (
        !readback
        || readback.status !== "quarantined"
        || readback.operation_id !== operationId
        || !readback.state_ref
      ) {
        return { accepted: false, reason: "target_quarantine_readback_unverified", reconciliation_required: true };
      }
      targetStateRef = readback.state_ref;
      if (readback.evidence_ref) evidenceRefs.push(readback.evidence_ref);
      executionStatus = "succeeded";
      reasonCode = "target_quarantine_state_readback_verified";
    }

    const protectionRecord: WardveilRecord = {
      contract_version: "0.1.0",
      record_type: "protection_action",
      record_id: `protect-${authDigest.slice(0, 32)}`,
      correlation_id: authorization.correlation_id,
      producer: { id: authorization.executor_id, authoritative: true },
      scope: authorization.scope,
      observed_at: observedAt,
      valid_until: policy.valid_until,
      evidence_refs: uniqueRefs(evidenceRefs),
      policy_decision: "quarantine",
      executor: authorization.executor_id,
      idempotency_key: authorization.idempotency_key,
      execution_status: executionStatus,
      reason_codes: [reasonCode],
    };

    let receipt: ExecutionReceipt;
    try {
      receipt = await this.env.WARDVEIL_PERSISTENCE_SERVICE.finalizeExecutionAuthorization(
        request.tenant_id,
        claim,
        protectionRecord,
      );
    } catch (_error) {
      return {
        accepted: false,
        reason: "execution_receipt_persistence_failed",
        protection_record: protectionRecord,
        reconciliation_required: true,
      };
    }

    const provenance = {
      authorization_id: authorization.authorization_id,
      issuer_id: authorization.issuer_id,
      executor_id: authorization.executor_id,
      signing_key_id: authorization.signing_key_id,
      signature_algorithm: authorization.signature_algorithm,
    };
    const receiptSuffix = receipt.receipt_id.replace(/^exec-receipt-/, "");
    const auditRecord: WardveilRecord = {
      contract_version: "0.1.0",
      record_type: "audit_event",
      record_id: `audit-quarantine-${receiptSuffix}`,
      correlation_id: authorization.correlation_id,
      producer: { id: "wardveil-audit-runtime", authoritative: true },
      scope: authorization.scope,
      observed_at: observedAt,
      evidence_refs: uniqueRefs([receipt.receipt_id, targetResult.evidence_ref, targetStateRef]),
      event_type: "quarantine.execution",
      outcome: executionStatus === "succeeded" ? "success" : "failure",
      actor_id: authorization.executor_id,
      authorization_provenance: provenance,
    };

    let quarantineRecord: WardveilRecord | undefined;
    if (executionStatus === "succeeded") {
      quarantineRecord = {
        contract_version: "0.1.0",
        record_type: "quarantine_record",
        record_id: `quarantine-${authDigest.slice(0, 32)}`,
        correlation_id: authorization.correlation_id,
        producer: { id: authorization.executor_id, authoritative: true },
        scope: authorization.scope,
        observed_at: observedAt,
        evidence_refs: uniqueRefs([...evidenceRefs, receipt.receipt_id, targetStateRef]),
        review_state: "pending",
        reason: request.reason,
        source_record_ids: [policy.record_id, protectionRecord.record_id],
        destructive_action: false,
        target_state_ref: targetStateRef,
      };
      auditRecord.evidence_refs = uniqueRefs([...auditRecord.evidence_refs, quarantineRecord.record_id]);
    }

    let evidencePersistenceDegraded = false;
    try {
      if (quarantineRecord) {
        await this.env.WARDVEIL_PERSISTENCE_SERVICE.append(request.tenant_id, quarantineRecord, "incident_evidence");
      }
      await this.env.WARDVEIL_PERSISTENCE_SERVICE.append(request.tenant_id, auditRecord, "audit_evidence");
    } catch (_error) {
      evidencePersistenceDegraded = true;
    }

    return {
      accepted: executionStatus === "succeeded",
      reason: evidencePersistenceDegraded
        ? "execution_finalized_evidence_persistence_degraded"
        : executionStatus === "succeeded"
          ? "quarantine_execution_finalized"
          : "target_quarantine_failed",
      receipt,
      protection_record: protectionRecord,
      quarantine_record: quarantineRecord,
      audit_record: auditRecord,
      evidence_persistence_degraded: evidencePersistenceDegraded || undefined,
    };
  }
}
