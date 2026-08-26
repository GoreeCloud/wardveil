type ProbeEvidence = {
  requirement: string;
  state: "passed" | "failed" | "pending";
  observed_at: string;
  detail: Record<string, unknown>;
};

type ProbeResult = {
  schema_version: 1;
  component: string;
  probe: string;
  revision: string;
  status: "unaccepted" | "degraded";
  evidence: ProbeEvidence[];
  security_state_authority: false;
  protection_claim_authority: false;
  everkeep_recovery_authority_preserved: true;
};

type Env = {
  WARDVEIL_ACCEPTANCE_PROBE: {
    runAcceptance(expectedRevision: string): Promise<ProbeResult>;
    runObservabilityFailure(expectedRevision: string, marker: string): Promise<{ marker: string; expected_failure_observed: boolean }>;
  };
};

function validRevision(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{40}$/.test(value);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/healthz" && request.method === "GET") {
      return Response.json({ service: "goreecloud-wardveil-acceptance-runner", mode: "local-only" });
    }
    if (request.method !== "POST" || !["/run", "/observe-failure"].includes(url.pathname)) {
      return new Response("Not Found", { status: 404 });
    }

    let body: { revision?: unknown; marker?: unknown };
    try {
      body = await request.json() as { revision?: unknown; marker?: unknown };
    } catch {
      return Response.json({ error: "invalid_json" }, { status: 400 });
    }

    if (!validRevision(body.revision)) {
      return Response.json({ error: "invalid_revision" }, { status: 400 });
    }

    try {
      if (url.pathname === "/observe-failure") {
        if (typeof body.marker !== "string" || !/^acceptance-[0-9a-f-]{36}$/.test(body.marker)) {
          return Response.json({ error: "invalid_marker" }, { status: 400 });
        }
        return Response.json(await env.WARDVEIL_ACCEPTANCE_PROBE.runObservabilityFailure(body.revision, body.marker));
      }
      const result = await env.WARDVEIL_ACCEPTANCE_PROBE.runAcceptance(body.revision);
      return Response.json(result, { status: result.status === "degraded" ? 503 : 200 });
    } catch (error) {
      return Response.json({ error: error instanceof Error ? error.message : String(error) }, { status: 502 });
    }
  },
} satisfies ExportedHandler<Env>;
