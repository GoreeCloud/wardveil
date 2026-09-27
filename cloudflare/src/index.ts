import { DurableObject, WorkerEntrypoint } from "cloudflare:workers";

const SCHEMA_VERSION = 1;
const EXECUTION_STATE_SCHEMA_VERSION = 1;
const ACCEPTANCE_TENANT_ID = "wardveil-runtime-acceptance";
const RETENTION_MS: Record<string, number> = {
  transient: 24 * 60 * 60 * 1000,
  security_event: 30 * 24 * 60 * 60 * 1000,
  incident_evidence: 180 * 24 * 60 * 60 * 1000,
  audit_evidence: 365 * 24 * 60 * 60 * 1000,
};
const RETENTION_ALARM_MS = 6 * 60 * 60 * 1000;
const EXECUTION_CLAIM_RETENTION_MS = 24 * 60 * 60 * 1000;
const MAX_AUTHORIZATION_TTL_MS = 5 * 60 * 1000;
const AUTHORIZATION_CLOCK_SKEW_MS = 30 * 1000;
const POLICY_ACTIONS = new Set([
  "allow", "allow_and_log", "warn", "step_up", "restrict",
  "quarantine", "revoke", "block", "isolate", "escalate",
]);
const FINAL_EXECUTION_OUTCOMES = new Set(["succeeded", "rejected", "failed"]);

type WardveilRecord = {
  record_id: string;
  record_type: string;
  correlation_id: string;
  observed_at: string;
  producer: { id: string; authoritative: boolean };
  scope: { resource_type: string; resource_id: string; [key: string]: unknown };
  valid_until?: string;
  [key: string]: unknown;
};

type ExecutionAuthorizationClaim = {
  authorization_id: string;
  authorization_digest_sha256: string;
  correlation_id: string;
  executor_id: string;
  action: string;
  scope: { resource_type: string; resource_id: string; [key: string]: unknown };
  idempotency_key: string;
  nonce: string;
  issued_at: string;
  expires_at: string;
};

type ExecutionReceiptPayload = {
  contract_version: "0.1.0";
  receipt_id: string;
  nonce: string;
  authorization_id: string;
  authorization_digest_sha256: string;
  executor_id: string;
  action: string;
  correlation_id: string;
  scope: Record<string, unknown>;
  idempotency_key: string;
  outcome: string;
  protection_record: WardveilRecord;
  protection_record_digest_sha256: string;
  completed_at: string;
  receipt_digest_sha256: string;
};

type ExecutionClaimDecision = {
  status: "new" | "execution_reconciliation_required" | "idempotent_finalized";
  receipt?: ExecutionReceiptPayload;
};

type Bindings = {
  WARDVEIL_PERSISTENCE: DurableObjectNamespace<WardveilPersistenceDO>;
};

type StoredRecord = {
  sequence: number;
  record_id: string;
  record_type: string;
  correlation_id: string;
  stored_at: string;
  expires_at: string;
  retention_class: string;
  digest: string;
  payload: WardveilRecord;
};

type MaintenanceEvidence = {
  id: number;
  event_type: string;
  occurred_at: string;
  detail: Record<string, unknown>;
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

function requireRecord(record: WardveilRecord): void {
  if (!record || typeof record !== "object") throw new Error("invalid_record");
  if (!record.record_id || !record.record_type || !record.correlation_id || !record.observed_at) throw new Error("invalid_record");
  if (!record.producer?.id || record.producer.authoritative !== true) throw new Error("non_authoritative_record");
  if (!record.scope?.resource_type || !record.scope?.resource_id) throw new Error("invalid_scope");
}

function parseTime(value: unknown, reason: string): number {
  if (
    typeof value !== "string"
    || !value
    || value !== value.trim()
    || !/(?:Z|[+-]\d{2}:\d{2})$/.test(value)
  ) throw new Error(reason);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) throw new Error(reason);
  return parsed;
}

function addBoundedMilliseconds(value: number, delta: number, reason: string): number {
  const result = value + delta;
  if (!Number.isSafeInteger(result) || !Number.isFinite(new Date(result).getTime())) {
    throw new Error(reason);
  }
  return result;
}

function requireExecutionAuthorizationClaim(claim: ExecutionAuthorizationClaim): void {
  if (!claim || typeof claim !== "object") throw new Error("invalid_execution_authorization_claim");
  for (const value of [
    claim.authorization_id, claim.authorization_digest_sha256, claim.correlation_id,
    claim.executor_id, claim.action, claim.idempotency_key, claim.nonce,
    claim.issued_at, claim.expires_at,
  ]) {
    if (!value || typeof value !== "string" || value.length > 256) throw new Error("invalid_execution_authorization_claim");
  }
  if (!/^[0-9a-f]{64}$/.test(claim.authorization_digest_sha256)) throw new Error("invalid_authorization_digest");
  if (!POLICY_ACTIONS.has(claim.action)) throw new Error("unsupported_policy_action");
  if (!claim.scope?.resource_type || !claim.scope?.resource_id) throw new Error("invalid_execution_scope");

  const now = Date.now();
  const issuedAt = parseTime(claim.issued_at, "invalid_authorization_time");
  const expiresAt = parseTime(claim.expires_at, "invalid_authorization_time");
  if (issuedAt > now + AUTHORIZATION_CLOCK_SKEW_MS) throw new Error("future_dated_authorization");
  if (expiresAt <= now) throw new Error("expired_authorization");
  if (expiresAt <= issuedAt || expiresAt - issuedAt > MAX_AUTHORIZATION_TTL_MS) throw new Error("invalid_authorization_validity_window");
}

function requireProtectionFinalization(claim: ExecutionAuthorizationClaim, record: WardveilRecord): string {
  requireRecord(record);
  if (record.record_type !== "protection_action") throw new Error("invalid_protection_record_type");
  const outcome = record.execution_status;
  if (typeof outcome !== "string" || !FINAL_EXECUTION_OUTCOMES.has(outcome)) throw new Error("invalid_protection_outcome");
  if (record.correlation_id !== claim.correlation_id) throw new Error("protection_correlation_mismatch");
  if (record.policy_decision !== claim.action) throw new Error("protection_action_mismatch");
  if (record.executor !== claim.executor_id) throw new Error("protection_executor_mismatch");
  if (record.idempotency_key !== claim.idempotency_key) throw new Error("protection_idempotency_mismatch");
  if (canonical(record.scope) !== canonical(claim.scope)) throw new Error("protection_scope_mismatch");
  return outcome;
}

export class WardveilPersistenceDO extends DurableObject<Bindings> {
  constructor(ctx: DurableObjectState, env: Bindings) {
    super(ctx, env);
    ctx.blockConcurrencyWhile(async () => {
      this.ctx.storage.transactionSync(() => {
        this.ctx.storage.sql.exec(`
          CREATE TABLE IF NOT EXISTS wardveil_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
          );
          CREATE TABLE IF NOT EXISTS wardveil_records (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            record_id TEXT NOT NULL UNIQUE,
            record_type TEXT NOT NULL,
            correlation_id TEXT NOT NULL,
            stored_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            retention_class TEXT NOT NULL,
            digest TEXT NOT NULL,
            payload_json TEXT NOT NULL
          );
          CREATE INDEX IF NOT EXISTS idx_records_correlation ON wardveil_records(correlation_id, sequence);
          CREATE INDEX IF NOT EXISTS idx_records_expiry ON wardveil_records(expires_at);
          CREATE TABLE IF NOT EXISTS consumer_checkpoints (
            consumer_id TEXT PRIMARY KEY,
            sequence INTEGER NOT NULL,
            updated_at TEXT NOT NULL
          );
          CREATE TABLE IF NOT EXISTS maintenance_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            detail_json TEXT NOT NULL
          );
          CREATE TABLE IF NOT EXISTS execution_authorization_claims (
            nonce TEXT PRIMARY KEY,
            authorization_id TEXT NOT NULL,
            authorization_digest_sha256 TEXT NOT NULL,
            correlation_id TEXT NOT NULL,
            executor_id TEXT NOT NULL,
            action TEXT NOT NULL,
            scope_json TEXT NOT NULL,
            idempotency_key TEXT NOT NULL,
            issued_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            claimed_at TEXT NOT NULL,
            retention_until TEXT NOT NULL,
            status TEXT NOT NULL,
            UNIQUE(executor_id, idempotency_key)
          );
          CREATE INDEX IF NOT EXISTS idx_execution_claim_retention ON execution_authorization_claims(retention_until);
          CREATE TABLE IF NOT EXISTS execution_receipts (
            receipt_id TEXT PRIMARY KEY,
            nonce TEXT NOT NULL UNIQUE,
            authorization_id TEXT NOT NULL,
            authorization_digest_sha256 TEXT NOT NULL,
            outcome TEXT NOT NULL,
            protection_record_digest_sha256 TEXT NOT NULL,
            completed_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            receipt_digest_sha256 TEXT NOT NULL,
            payload_json TEXT NOT NULL
          );
          CREATE INDEX IF NOT EXISTS idx_execution_receipt_expiry ON execution_receipts(expires_at);
        `);
        const existing = this.ctx.storage.sql.exec<{ value: string }>("SELECT value FROM wardveil_meta WHERE key='schema_version'").toArray();
        if (existing.length === 0) {
          this.ctx.storage.sql.exec("INSERT INTO wardveil_meta(key,value) VALUES('schema_version',?)", String(SCHEMA_VERSION));
        } else if (Number(existing[0].value) !== SCHEMA_VERSION) {
          throw new Error("unsupported_schema_version");
        }
        const executionState = this.ctx.storage.sql.exec<{ value: string }>("SELECT value FROM wardveil_meta WHERE key='execution_state_schema_version'").toArray();
        if (executionState.length === 0) {
          this.ctx.storage.sql.exec("INSERT INTO wardveil_meta(key,value) VALUES('execution_state_schema_version',?)", String(EXECUTION_STATE_SCHEMA_VERSION));
        } else if (Number(executionState[0].value) !== EXECUTION_STATE_SCHEMA_VERSION) {
          throw new Error("unsupported_execution_state_schema_version");
        }
      });
      if ((await this.ctx.storage.getAlarm()) === null) {
        await this.ctx.storage.setAlarm(Date.now() + RETENTION_ALARM_MS);
      }
    });
  }

  async append(record: WardveilRecord, retentionClass = "security_event"): Promise<StoredRecord> {
    requireRecord(record);
    const retentionMs = RETENTION_MS[retentionClass];
    if (!retentionMs) throw new Error("unsupported_retention_class");

    const now = new Date();
    const expiresAt = new Date(now.getTime() + retentionMs);
    const payloadJson = canonical(record);
    const digest = await sha256Hex(payloadJson);

    const row = this.ctx.storage.transactionSync(() => {
      const duplicate = this.ctx.storage.sql.exec<{ record_id: string }>("SELECT record_id FROM wardveil_records WHERE record_id=?", record.record_id).toArray();
      if (duplicate.length) throw new Error("duplicate_record_id");
      return this.ctx.storage.sql.exec<{ sequence: number }>(
        `INSERT INTO wardveil_records(record_id,record_type,correlation_id,stored_at,expires_at,retention_class,digest,payload_json)
         VALUES(?,?,?,?,?,?,?,?) RETURNING sequence`,
        record.record_id,
        record.record_type,
        record.correlation_id,
        now.toISOString(),
        expiresAt.toISOString(),
        retentionClass,
        digest,
        payloadJson,
      ).one();
    });

    return {
      sequence: row.sequence,
      record_id: record.record_id,
      record_type: record.record_type,
      correlation_id: record.correlation_id,
      stored_at: now.toISOString(),
      expires_at: expiresAt.toISOString(),
      retention_class: retentionClass,
      digest,
      payload: record,
    };
  }

  async readAfter(sequence: number, limit = 100): Promise<StoredRecord[]> {
    const safeLimit = Math.max(1, Math.min(500, Math.trunc(limit)));
    const rows = this.ctx.storage.sql.exec<{
      sequence: number; record_id: string; record_type: string; correlation_id: string;
      stored_at: string; expires_at: string; retention_class: string; digest: string; payload_json: string;
    }>(
      `SELECT sequence,record_id,record_type,correlation_id,stored_at,expires_at,retention_class,digest,payload_json
       FROM wardveil_records WHERE sequence>? AND expires_at>? ORDER BY sequence ASC LIMIT ?`,
      Math.max(0, Math.trunc(sequence)), new Date().toISOString(), safeLimit,
    ).toArray();
    return rows.map((row) => ({ ...row, payload: JSON.parse(row.payload_json) as WardveilRecord }));
  }

  async checkpoint(consumerId: string, sequence: number): Promise<void> {
    if (!consumerId || sequence < 0 || !Number.isInteger(sequence)) throw new Error("invalid_checkpoint");
    const now = new Date().toISOString();
    this.ctx.storage.transactionSync(() => {
      const current = this.ctx.storage.sql.exec<{ sequence: number }>("SELECT sequence FROM consumer_checkpoints WHERE consumer_id=?", consumerId).toArray();
      if (current.length && sequence < current[0].sequence) throw new Error("checkpoint_regression");
      this.ctx.storage.sql.exec(
        `INSERT INTO consumer_checkpoints(consumer_id,sequence,updated_at) VALUES(?,?,?)
         ON CONFLICT(consumer_id) DO UPDATE SET sequence=excluded.sequence,updated_at=excluded.updated_at`,
        consumerId, sequence, now,
      );
    });
  }

  async getCheckpoint(consumerId: string): Promise<number> {
    const rows = this.ctx.storage.sql.exec<{ sequence: number }>("SELECT sequence FROM consumer_checkpoints WHERE consumer_id=?", consumerId).toArray();
    return rows.length ? rows[0].sequence : 0;
  }

  async claimExecutionAuthorization(claim: ExecutionAuthorizationClaim): Promise<ExecutionClaimDecision> {
    requireExecutionAuthorizationClaim(claim);
    const now = new Date();
    const retentionBase = Math.max(parseTime(claim.expires_at, "invalid_authorization_time"), now.getTime());
    const retentionUntil = new Date(
      addBoundedMilliseconds(retentionBase, EXECUTION_CLAIM_RETENTION_MS, "invalid_authorization_time"),
    ).toISOString();
    const scopeJson = canonical(claim.scope);

    return this.ctx.storage.transactionSync(() => {
      const existing = this.ctx.storage.sql.exec<{
        authorization_id: string; authorization_digest_sha256: string; executor_id: string;
        idempotency_key: string; status: string;
      }>(
        `SELECT authorization_id,authorization_digest_sha256,executor_id,idempotency_key,status
         FROM execution_authorization_claims WHERE nonce=?`,
        claim.nonce,
      ).toArray();

      if (existing.length) {
        const row = existing[0];
        if (
          row.authorization_id !== claim.authorization_id
          || row.authorization_digest_sha256 !== claim.authorization_digest_sha256
          || row.executor_id !== claim.executor_id
          || row.idempotency_key !== claim.idempotency_key
        ) {
          throw new Error("authorization_nonce_conflict");
        }
        const receiptRows = this.ctx.storage.sql.exec<{ payload_json: string }>(
          "SELECT payload_json FROM execution_receipts WHERE nonce=?",
          claim.nonce,
        ).toArray();
        if (receiptRows.length) {
          return { status: "idempotent_finalized", receipt: JSON.parse(receiptRows[0].payload_json) as ExecutionReceiptPayload };
        }
        return { status: "execution_reconciliation_required" };
      }

      const idem = this.ctx.storage.sql.exec<{ nonce: string }>(
        "SELECT nonce FROM execution_authorization_claims WHERE executor_id=? AND idempotency_key=?",
        claim.executor_id,
        claim.idempotency_key,
      ).toArray();
      if (idem.length && idem[0].nonce !== claim.nonce) throw new Error("executor_idempotency_conflict");

      this.ctx.storage.sql.exec(
        `INSERT INTO execution_authorization_claims(
          nonce,authorization_id,authorization_digest_sha256,correlation_id,executor_id,action,scope_json,
          idempotency_key,issued_at,expires_at,claimed_at,retention_until,status
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        claim.nonce,
        claim.authorization_id,
        claim.authorization_digest_sha256,
        claim.correlation_id,
        claim.executor_id,
        claim.action,
        scopeJson,
        claim.idempotency_key,
        claim.issued_at,
        claim.expires_at,
        now.toISOString(),
        retentionUntil,
        "claimed",
      );
      return { status: "new" };
    });
  }

  async finalizeExecutionAuthorization(
    claim: ExecutionAuthorizationClaim,
    protectionRecord: WardveilRecord,
  ): Promise<ExecutionReceiptPayload> {
    requireExecutionAuthorizationClaim(claim);
    const outcome = requireProtectionFinalization(claim, protectionRecord);
    const protectionRecordDigest = await sha256Hex(canonical(protectionRecord));
    const receiptIdentity = {
      authorization_digest_sha256: claim.authorization_digest_sha256,
      protection_record_digest_sha256: protectionRecordDigest,
      outcome,
      executor_id: claim.executor_id,
      idempotency_key: claim.idempotency_key,
    };
    const receiptId = `exec-receipt-${(await sha256Hex(canonical(receiptIdentity))).slice(0, 32)}`;
    const completedAt = new Date().toISOString();
    const receiptWithoutDigest = {
      contract_version: "0.1.0" as const,
      receipt_id: receiptId,
      nonce: claim.nonce,
      authorization_id: claim.authorization_id,
      authorization_digest_sha256: claim.authorization_digest_sha256,
      executor_id: claim.executor_id,
      action: claim.action,
      correlation_id: claim.correlation_id,
      scope: claim.scope,
      idempotency_key: claim.idempotency_key,
      outcome,
      protection_record: protectionRecord,
      protection_record_digest_sha256: protectionRecordDigest,
      completed_at: completedAt,
    };
    const receiptDigest = await sha256Hex(canonical(receiptWithoutDigest));
    const receipt: ExecutionReceiptPayload = { ...receiptWithoutDigest, receipt_digest_sha256: receiptDigest };
    const expiresAt = new Date(Date.now() + RETENTION_MS.audit_evidence).toISOString();

    return this.ctx.storage.transactionSync(() => {
      const claimed = this.ctx.storage.sql.exec<{
        authorization_id: string; authorization_digest_sha256: string; correlation_id: string;
        executor_id: string; action: string; scope_json: string; idempotency_key: string;
      }>(
        `SELECT authorization_id,authorization_digest_sha256,correlation_id,executor_id,action,scope_json,idempotency_key
         FROM execution_authorization_claims WHERE nonce=?`,
        claim.nonce,
      ).toArray();
      if (!claimed.length) throw new Error("execution_claim_required");
      const row = claimed[0];
      if (row.authorization_id !== claim.authorization_id || row.authorization_digest_sha256 !== claim.authorization_digest_sha256) {
        throw new Error("authorization_claim_binding_mismatch");
      }
      if (
        row.correlation_id !== claim.correlation_id || row.executor_id !== claim.executor_id
        || row.action !== claim.action || row.idempotency_key !== claim.idempotency_key
        || row.scope_json !== canonical(claim.scope)
      ) {
        throw new Error("authorization_claim_binding_mismatch");
      }

      const existing = this.ctx.storage.sql.exec<{
        protection_record_digest_sha256: string; outcome: string; payload_json: string;
      }>(
        "SELECT protection_record_digest_sha256,outcome,payload_json FROM execution_receipts WHERE nonce=?",
        claim.nonce,
      ).toArray();
      if (existing.length) {
        if (existing[0].protection_record_digest_sha256 !== protectionRecordDigest || existing[0].outcome !== outcome) {
          throw new Error("execution_receipt_conflict");
        }
        return JSON.parse(existing[0].payload_json) as ExecutionReceiptPayload;
      }

      this.ctx.storage.sql.exec(
        `INSERT INTO execution_receipts(
          receipt_id,nonce,authorization_id,authorization_digest_sha256,outcome,
          protection_record_digest_sha256,completed_at,expires_at,receipt_digest_sha256,payload_json
        ) VALUES(?,?,?,?,?,?,?,?,?,?)`,
        receipt.receipt_id,
        claim.nonce,
        claim.authorization_id,
        claim.authorization_digest_sha256,
        outcome,
        protectionRecordDigest,
        completedAt,
        expiresAt,
        receiptDigest,
        canonical(receipt),
      );
      this.ctx.storage.sql.exec(
        "UPDATE execution_authorization_claims SET status=? WHERE nonce=?",
        outcome,
        claim.nonce,
      );
      return receipt;
    });
  }

  async getExecutionReceipt(nonce: string): Promise<ExecutionReceiptPayload | null> {
    if (!nonce || nonce.length > 256) throw new Error("invalid_execution_nonce");
    const rows = this.ctx.storage.sql.exec<{ payload_json: string }>(
      "SELECT payload_json FROM execution_receipts WHERE nonce=? AND expires_at>?",
      nonce,
      new Date().toISOString(),
    ).toArray();
    return rows.length ? JSON.parse(rows[0].payload_json) as ExecutionReceiptPayload : null;
  }

  async maintenanceEvidence(limit = 20): Promise<MaintenanceEvidence[]> {
    const safeLimit = Math.max(1, Math.min(100, Math.trunc(limit)));
    return this.ctx.storage.sql.exec<{ id: number; event_type: string; occurred_at: string; detail_json: string }>(
      "SELECT id,event_type,occurred_at,detail_json FROM maintenance_evidence ORDER BY id DESC LIMIT ?",
      safeLimit,
    ).toArray().map((row) => ({
      id: row.id,
      event_type: row.event_type,
      occurred_at: row.occurred_at,
      detail: JSON.parse(row.detail_json) as Record<string, unknown>,
    }));
  }

  async scheduleAcceptanceRetentionAlarm(delayMs: number): Promise<{ scheduled_for: string }> {
    const boundedDelay = Math.trunc(delayMs);
    if (boundedDelay < 1000 || boundedDelay > 60000) throw new Error("invalid_acceptance_alarm_delay");
    const scheduledFor = Date.now() + boundedDelay;
    await this.ctx.storage.setAlarm(scheduledFor);
    return { scheduled_for: new Date(scheduledFor).toISOString() };
  }

  async emitAcceptanceObservabilityFailure(marker: string): Promise<never> {
    if (!/^acceptance-[0-9a-f-]{36}$/.test(marker)) throw new Error("invalid_acceptance_marker");
    console.error(JSON.stringify({ event: "wardveil_acceptance_observability_probe", marker }));
    throw new Error("acceptance_observability_probe");
  }

  async health(): Promise<Record<string, unknown>> {
    const schema = this.ctx.storage.sql.exec<{ value: string }>("SELECT value FROM wardveil_meta WHERE key='schema_version'").one();
    const executionStateSchema = this.ctx.storage.sql.exec<{ value: string }>("SELECT value FROM wardveil_meta WHERE key='execution_state_schema_version'").one();
    const currentBookmark = await this.ctx.storage.getCurrentBookmark();
    return {
      adapter: "cloudflare-durable-object-sqlite",
      status: Number(schema.value) === SCHEMA_VERSION && Number(executionStateSchema.value) === EXECUTION_STATE_SCHEMA_VERSION ? "operational" : "degraded",
      schema_version: Number(schema.value),
      execution_state_schema_version: Number(executionStateSchema.value),
      database_size_bytes: this.ctx.storage.sql.databaseSize,
      encryption_at_rest: "cloudflare_managed",
      recovery: { pitr_available: true, current_bookmark: currentBookmark },
      execution_state: {
        replay_storage: "durable_object_sqlite",
        receipt_storage: "durable_object_sqlite",
        uncertain_outcome_behavior: "reconciliation_required",
      },
      security_state_authority: false,
      protection_claim_authority: false,
    };
  }

  async alarm(): Promise<void> {
    const now = new Date().toISOString();
    const removed = this.ctx.storage.transactionSync(() => {
      const recordCount = this.ctx.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM wardveil_records WHERE expires_at<=?", now).one().count;
      const claimCount = this.ctx.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM execution_authorization_claims WHERE retention_until<=?", now).one().count;
      const receiptCount = this.ctx.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM execution_receipts WHERE expires_at<=?", now).one().count;
      this.ctx.storage.sql.exec("DELETE FROM wardveil_records WHERE expires_at<=?", now);
      this.ctx.storage.sql.exec("DELETE FROM execution_authorization_claims WHERE retention_until<=?", now);
      this.ctx.storage.sql.exec("DELETE FROM execution_receipts WHERE expires_at<=?", now);
      this.ctx.storage.sql.exec(
        "INSERT INTO maintenance_evidence(event_type,occurred_at,detail_json) VALUES(?,?,?)",
        "retention_enforced",
        now,
        JSON.stringify({ removed_records: recordCount, removed_execution_claims: claimCount, removed_execution_receipts: receiptCount }),
      );
      return { recordCount, claimCount, receiptCount };
    });
    console.log(JSON.stringify({
      event: "wardveil_retention_enforced",
      removed_records: removed.recordCount,
      removed_execution_claims: removed.claimCount,
      removed_execution_receipts: removed.receiptCount,
    }));
    await this.ctx.storage.setAlarm(Date.now() + RETENTION_ALARM_MS);
  }
}

export default class WardveilPersistenceWorker extends WorkerEntrypoint<Bindings> {
  private stub(tenantId: string) {
    if (!tenantId || tenantId.length > 128) throw new Error("invalid_tenant_id");
    return this.env.WARDVEIL_PERSISTENCE.getByName(tenantId);
  }

  private acceptanceStub(tenantId: string) {
    if (tenantId !== ACCEPTANCE_TENANT_ID) throw new Error("acceptance_tenant_required");
    return this.stub(tenantId);
  }

  async append(tenantId: string, record: WardveilRecord, retentionClass = "security_event") {
    return this.stub(tenantId).append(record, retentionClass);
  }

  async readAfter(tenantId: string, sequence: number, limit = 100) {
    return this.stub(tenantId).readAfter(sequence, limit);
  }

  async checkpoint(tenantId: string, consumerId: string, sequence: number) {
    return this.stub(tenantId).checkpoint(consumerId, sequence);
  }

  async getCheckpoint(tenantId: string, consumerId: string) {
    return this.stub(tenantId).getCheckpoint(consumerId);
  }

  async claimExecutionAuthorization(tenantId: string, claim: ExecutionAuthorizationClaim) {
    return this.stub(tenantId).claimExecutionAuthorization(claim);
  }

  async finalizeExecutionAuthorization(tenantId: string, claim: ExecutionAuthorizationClaim, protectionRecord: WardveilRecord) {
    return this.stub(tenantId).finalizeExecutionAuthorization(claim, protectionRecord);
  }

  async getExecutionReceipt(tenantId: string, nonce: string) {
    return this.stub(tenantId).getExecutionReceipt(nonce);
  }

  async health(tenantId: string) {
    return this.stub(tenantId).health();
  }

  async maintenanceEvidence(tenantId: string, limit = 20) {
    return this.stub(tenantId).maintenanceEvidence(limit);
  }

  async scheduleAcceptanceRetentionAlarm(tenantId: string, delayMs = 2000) {
    return this.acceptanceStub(tenantId).scheduleAcceptanceRetentionAlarm(delayMs);
  }

  async emitAcceptanceObservabilityFailure(tenantId: string, marker: string) {
    return this.acceptanceStub(tenantId).emitAcceptanceObservabilityFailure(marker);
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/healthz") {
      return Response.json({ service: "wardveil-persistence", status: "reachable", mutation_api: "service-binding-rpc-only" });
    }
    return new Response("Not Found", { status: 404 });
  }
}
