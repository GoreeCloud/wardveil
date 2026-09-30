# GoreeCloud Observability v1 Integration — Wardveil Security

**Status:** Weave source adoption only. Live Observability runtime acceptance remains incomplete.

Wardveil constructs privacy-minimized operational signals against the authoritative GoreeCloud Observability v1 contract at repository revision `a7f6a65f442d3e517baddbe7b6ce7c250d142c8c`.

## Evidence boundary

Operational signals are evidence, not protection authority. A healthy/degraded/failed signal cannot by itself establish Protected/Covered status, execution success, production readiness, or Anchor qualification.

The source adapter:

- preserves the complete Observability nine-state vocabulary;
- enforces the contract TTL range;
- requires explicit timezone-qualified observation/collection times;
- rejects collection time before observation time;
- retains explicit unknown, stale, partially observed, unavailable, and not-monitored states;
- rejects contradictory `healthy` state when collection gaps are declared; and
- recursively excludes secret-bearing and privacy-sensitive attributes.

Raw private content and reusable credentials are excluded. Direct user, session, device, account, network-address, content, payload, message, query, and body identifiers are not accepted as ordinary signal attributes.

Source adoption does not establish live Observability acceptance. Production acceptance still requires authenticated producer identity, approved publication/collection transport, freshness/completeness policy, retention/deletion controls, diagnostics/alerting, target-environment evidence, recovery behavior, and operational acceptance.
