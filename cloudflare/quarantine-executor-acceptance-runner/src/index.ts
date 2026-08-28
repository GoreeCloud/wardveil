type ExecuteResponse = {
  accepted: boolean;
  reason: string;
  reconciliation_required?: boolean;
};

type QuarantineExecutorService = {
  executeQuarantine(request: {
    tenant_id: string;
    policy_record: Record<string, unknown>;
    authorization: Record<string, unknown>;
    reason: string;
  }): Promise<ExecuteResponse>;
};

type Env = {
  WARDVEIL_QUARANTINE_EXECUTOR: QuarantineExecutorService;
  EXPECTED_REVISION: string;
};

function validRevision(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{40}$/.test(value);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/healthz") {
      return Response.json({
        service: "goreecloud-wardveil-quarantine-executor-acceptance-runner",
        mode: "local-only",
      });
    }
    if (request.method !== "POST" || url.pathname !== "/probe") {
      return new Response("Not Found", { status: 404 });
    }

    let body: { revision?: unknown };
    try {
      body = await request.json() as { revision?: unknown };
    } catch {
      return Response.json({ error: "invalid_json" }, { status: 400 });
    }
    if (!validRevision(body.revision) || body.revision !== env.EXPECTED_REVISION) {
      return Response.json({ error: "revision_mismatch" }, { status: 400 });
    }

    try {
      // This is deliberately non-mutating. A configured executor checks its
      // deployment target before validating the deliberately invalid policy.
      // The exact rejection therefore proves internal RPC reachability and
      // that the runtime no longer carries REPLACE_AT_DEPLOYMENT, without
      // authorizing or invoking a quarantine side effect.
      const result = await env.WARDVEIL_QUARANTINE_EXECUTOR.executeQuarantine({
        tenant_id: "wardveil-runtime-acceptance",
        policy_record: {},
        authorization: {},
        reason: "deployment transport probe",
      });
      const passed = result.accepted === false && result.reason === "invalid_policy_record";
      return Response.json({
        schema_version: 1,
        revision: body.revision,
        passed,
        expected_rejection: "invalid_policy_record",
        observed_rejection: result.reason,
        quarantine_side_effect_authorized: false,
        production_runtime_status: "unaccepted",
      }, { status: passed ? 200 : 503 });
    } catch (error) {
      return Response.json({
        error: error instanceof Error ? error.message : String(error),
        quarantine_side_effect_authorized: false,
      }, { status: 502 });
    }
  },
} satisfies ExportedHandler<Env>;
