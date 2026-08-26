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
  };
};

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/healthz" && request.method === "GET") {
      return Response.json({ service: "goreecloud-wardveil-acceptance-runner", mode: "local-only" });
    }
    if (url.pathname !== "/run" || request.method !== "POST") {
      return new Response("Not Found", { status: 404 });
    }

    let revision = "";
    try {
      const body = await request.json() as { revision?: unknown };
      if (typeof body.revision === "string") revision = body.revision;
    } catch {
      return Response.json({ error: "invalid_json" }, { status: 400 });
    }

    if (!/^[0-9a-f]{40}$/.test(revision)) {
      return Response.json({ error: "invalid_revision" }, { status: 400 });
    }

    try {
      const result = await env.WARDVEIL_ACCEPTANCE_PROBE.runAcceptance(revision);
      return Response.json(result, { status: result.status === "degraded" ? 503 : 200 });
    } catch (error) {
      return Response.json({ error: error instanceof Error ? error.message : String(error) }, { status: 502 });
    }
  },
} satisfies ExportedHandler<Env>;
