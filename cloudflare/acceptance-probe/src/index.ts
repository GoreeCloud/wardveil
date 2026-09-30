import { WorkerEntrypoint } from "cloudflare:workers";

type WardveilRecord = {
  record_id: string;
  record_type: string;
  correlation_id: string;
  observed_at: string;
  producer: { id: string; authoritative: boolean };
  scope: { resource_type: string; resource_id: string };
  [key: string]: unknown;
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

type PersistenceService = {
  append(tenantId: string, record: WardveilRecord, retentionClass?: string): Promise<StoredRecord>;
  readAfter(tenantId: string, sequence: number, limit?: number): Promise<StoredRecord[]>;
  checkpoint(tenantId: string, consumerId: string, sequence: number): Promise<void>;
  getCheckpoint(tenantId: string, consumerId: string): Promise<number>;
  health(tenantId: string): Promise<Record<string, unknown>>;
  maintenanceEvidence(tenantId: string, limit?: number): Promise<MaintenanceEvidence[]>;
  scheduleAcceptanceRetentionAlarm(tenantId: string, delayMs?: number): Promise<{ scheduled_for: string }>;
  emitAcceptanceObservabilityFailure(tenantId: string, marker: string): Promise<never>;
};

type Bindings = {
  WARDVEIL_PERSISTENCE_SERVICE: PersistenceService;
  ACCEPTANCE_TENANT: string;
  EXPECTED_REVISION: string;
};

type EvidenceState = "passed" | "failed" | "pending";

type EvidenceItem = {
  requirement: string;
  state: EvidenceState;
  observed_at: string;
  detail: Record<string, unknown>;
};

type ProbeResult = {
  schema_version: 1;
  component: "Wardveil Cloudflare persistence runtime";
  probe: "goreecloud-wardveil-acceptance-probe";
  revision: string;
  status: "unaccepted" | "degraded";
  evidence: EvidenceItem[];
  security_state_authority: false;
  protection_claim_authority: false;
  everkeep_recovery_authority_preserved: true;
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

function errorCode(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function evidence(requirement: string, state: EvidenceState, detail: Record<string, unknown>): EvidenceItem {
  return { requirement, state, observed_at: new Date().toISOString(), detail };
}

function requireRevision(expectedRevision: string, configuredRevision: string): void {
  if (!expectedRevision || expectedRevision !== configuredRevision || expectedRevision === "UNSET_AT_DEPLOYMENT") {
    throw new Error("revision_mismatch");
  }
}

export default class WardveilAcceptanceProbe extends WorkerEntrypoint<Bindings> {
  async runAcceptance(expectedRevision: string): Promise<ProbeResult> {
    requireRevision(expectedRevision, this.env.EXPECTED_REVISION);
    const tenantId = this.env.ACCEPTANCE_TENANT;
    if (!tenantId) throw new Error("acceptance_tenant_missing");

    const now = new Date().toISOString();
    const nonce = crypto.randomUUID();
    const record: WardveilRecord = {
      record_id: `acceptance-${nonce}`,
      record_type: "audit_event",
      correlation_id: `acceptance-${nonce}`,
      observed_at: now,
      producer: { id: "goreecloud-wardveil-acceptance-probe", authoritative: true },
      scope: { resource_type: "runtime_acceptance", resource_id: expectedRevision },
      event_type: "runtime_acceptance_probe",
      outcome: "test_only",
      test_only: true,
    };

    const results: EvidenceItem[] = [];
    let stored: StoredRecord | null = null;

    try {
      stored = await this.env.WARDVEIL_PERSISTENCE_SERVICE.append(tenantId, record, "transient");
      const readback = await this.env.WARDVEIL_PERSISTENCE_SERVICE.readAfter(tenantId, Math.max(0, stored.sequence - 1), 10);
      const matched = readback.find((candidate) => candidate.record_id === record.record_id);
      results.push(evidence("authorized_append_read", matched ? "passed" : "failed", {
        record_id: record.record_id,
        sequence: stored.sequence,
        readback_match: Boolean(matched),
      }));
    } catch (error) {
      results.push(evidence("authorized_append_read", "failed", { error: errorCode(error) }));
    }

    if (stored) {
      try {
        await this.env.WARDVEIL_PERSISTENCE_SERVICE.append(tenantId, record, "transient");
        results.push(evidence("duplicate_record_rejection", "failed", { error: "duplicate_was_accepted" }));
      } catch (error) {
        const code = errorCode(error);
        results.push(evidence("duplicate_record_rejection", code.includes("duplicate_record_id") ? "passed" : "failed", { error: code }));
      }

      try {
        const expectedDigest = await sha256Hex(canonical(record));
        results.push(evidence("payload_digest_verification", expectedDigest === stored.digest ? "passed" : "failed", {
          record_id: record.record_id,
          expected_digest: expectedDigest,
          stored_digest: stored.digest,
        }));
      } catch (error) {
        results.push(evidence("payload_digest_verification", "failed", { error: errorCode(error) }));
      }

      const consumerId = `acceptance-consumer-${nonce}`;
      try {
        await this.env.WARDVEIL_PERSISTENCE_SERVICE.checkpoint(tenantId, consumerId, stored.sequence);
        const accepted = await this.env.WARDVEIL_PERSISTENCE_SERVICE.getCheckpoint(tenantId, consumerId);
        let regressionRejected = false;
        try {
          await this.env.WARDVEIL_PERSISTENCE_SERVICE.checkpoint(tenantId, consumerId, Math.max(0, stored.sequence - 1));
        } catch (error) {
          regressionRejected = errorCode(error).includes("checkpoint_regression");
        }
        const finalCheckpoint = await this.env.WARDVEIL_PERSISTENCE_SERVICE.getCheckpoint(tenantId, consumerId);
        const passed = accepted === stored.sequence && finalCheckpoint === stored.sequence && regressionRejected;
        results.push(evidence("checkpoint_non_regression", passed ? "passed" : "failed", {
          accepted_checkpoint: accepted,
          final_checkpoint: finalCheckpoint,
          regression_rejected: regressionRejected,
        }));
      } catch (error) {
        results.push(evidence("checkpoint_non_regression", "failed", { error: errorCode(error) }));
      }
    } else {
      results.push(evidence("duplicate_record_rejection", "failed", { error: "append_prerequisite_failed" }));
      results.push(evidence("payload_digest_verification", "failed", { error: "append_prerequisite_failed" }));
      results.push(evidence("checkpoint_non_regression", "failed", { error: "append_prerequisite_failed" }));
    }

    try {
      const health = await this.env.WARDVEIL_PERSISTENCE_SERVICE.health(tenantId);
      const recovery = (health.recovery ?? {}) as Record<string, unknown>;
      const pitrAvailable = recovery.pitr_available === true && typeof recovery.current_bookmark === "string";
      results.push(evidence("pitr_availability", pitrAvailable ? "passed" : "failed", {
        adapter: health.adapter,
        status: health.status,
        pitr_available: recovery.pitr_available,
        bookmark_present: typeof recovery.current_bookmark === "string",
      }));
    } catch (error) {
      results.push(evidence("pitr_availability", "failed", { error: errorCode(error) }));
    }

    try {
      const startedAt = Date.now();
      const scheduled = await this.env.WARDVEIL_PERSISTENCE_SERVICE.scheduleAcceptanceRetentionAlarm(tenantId, 2000);
      let retained: MaintenanceEvidence | undefined;
      for (let attempt = 0; attempt < 75; attempt += 1) {
        await new Promise((resolve) => setTimeout(resolve, 1000));
        const history = await this.env.WARDVEIL_PERSISTENCE_SERVICE.maintenanceEvidence(tenantId, 20);
        retained = history.find((item) => item.event_type === "retention_enforced" && Date.parse(item.occurred_at) >= startedAt);
        if (retained) break;
      }
      results.push(evidence("retention_alarm_evidence", retained ? "passed" : "failed", {
        scheduled_for: scheduled.scheduled_for,
        maintenance_event_id: retained?.id ?? null,
        maintenance_occurred_at: retained?.occurred_at ?? null,
        cloudflare_alarm_handler_observed: Boolean(retained),
      }));
    } catch (error) {
      results.push(evidence("retention_alarm_evidence", "failed", { error: errorCode(error) }));
    }

    for (const requirement of [
      "deployed_revision_match",
      "health_endpoint",
      "readiness_endpoint",
      "restore_verification_exercise",
      "observability_failure_evidence",
      "public_mutation_surface_absent",
    ]) {
      results.push(evidence(requirement, "pending", { reason: "requires_external_runtime_evidence" }));
    }

    const anyFailed = results.some((item) => item.state === "failed");
    return {
      schema_version: 1,
      component: "Wardveil Cloudflare persistence runtime",
      probe: "goreecloud-wardveil-acceptance-probe",
      revision: expectedRevision,
      status: anyFailed ? "degraded" : "unaccepted",
      evidence: results,
      security_state_authority: false,
      protection_claim_authority: false,
      everkeep_recovery_authority_preserved: true,
    };
  }

  async runObservabilityFailure(expectedRevision: string, marker: string): Promise<{ marker: string; expected_failure_observed: boolean }> {
    requireRevision(expectedRevision, this.env.EXPECTED_REVISION);
    if (!/^acceptance-[0-9a-f-]{36}$/.test(marker)) throw new Error("invalid_acceptance_marker");
    try {
      await this.env.WARDVEIL_PERSISTENCE_SERVICE.emitAcceptanceObservabilityFailure(this.env.ACCEPTANCE_TENANT, marker);
    } catch (error) {
      if (errorCode(error).includes("acceptance_observability_probe")) {
        return { marker, expected_failure_observed: true };
      }
      throw error;
    }
    throw new Error("acceptance_observability_probe_did_not_fail");
  }

  async fetch(): Promise<Response> {
    return new Response("Not Found", { status: 404 });
  }
}