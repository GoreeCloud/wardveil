import { DurableObject, WorkerEntrypoint } from "cloudflare:workers";

const SCHEMA_VERSION = 1;
const ACCEPTANCE_TENANT_ID = "wardveil-runtime-acceptance";
const RETENTION_MS: Record<string, number> = {
  transient: 24 * 60 * 60 * 1000,
  security_event: 30 * 24 * 60 * 60 * 1000,
  incident_evidence: 180 * 24 * 60 * 60 * 1000,
  audit_evidence: 365 * 24 * 60 * 60 * 1000,
};
const RETENTION_ALARM_MS = 6 * 60 * 60 * 1000;

type WardveilRecord = {
  record_id: string;
  record_type: string;
  correlation_id: string;
  observed_at: string;
  producer: { id: string; authoritative: boolean };
  scope: { resource_type: string; resource_id: string };
  valid_until?: string;
  [key: string]: unknown;
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
        `);
        const existing = this.ctx.storage.sql.exec<{ value: string }>("SELECT value FROM wardveil_meta WHERE key='schema_version'").toArray();
        if (existing.length === 0) {
          this.ctx.storage.sql.exec("INSERT INTO wardveil_meta(key,value) VALUES('schema_version',?)", String(SCHEMA_VERSION));
        } else if (Number(existing[0].value) !== SCHEMA_VERSION) {
          throw new Error("unsupported_schema_version");
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
    const currentBookmark = await this.ctx.storage.getCurrentBookmark();
    return {
      adapter: "cloudflare-durable-object-sqlite",
      status: Number(schema.value) === SCHEMA_VERSION ? "operational" : "degraded",
      schema_version: Number(schema.value),
      database_size_bytes: this.ctx.storage.sql.databaseSize,
      encryption_at_rest: "cloudflare_managed",
      recovery: { pitr_available: true, current_bookmark: currentBookmark },
      security_state_authority: false,
      protection_claim_authority: false,
    };
  }

  async alarm(): Promise<void> {
    const now = new Date().toISOString();
    const removed = this.ctx.storage.transactionSync(() => {
      const count = this.ctx.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM wardveil_records WHERE expires_at<=?", now).one().count;
      this.ctx.storage.sql.exec("DELETE FROM wardveil_records WHERE expires_at<=?", now);
      this.ctx.storage.sql.exec(
        "INSERT INTO maintenance_evidence(event_type,occurred_at,detail_json) VALUES(?,?,?)",
        "retention_enforced", now, JSON.stringify({ removed_records: count }),
      );
      return count;
    });
    console.log(JSON.stringify({ event: "wardveil_retention_enforced", removed_records: removed }));
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