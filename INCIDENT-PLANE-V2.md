# Wardveil Incident Plane — Next-Upgrade Source Contract

**Status:** Development / Source Candidate  
**Contract:** `urn:goreecloud:wardveil:incident:0.1.0`

The next-upgrade Incident Plane gives Wardveil a first-class, evidence-driven incident record for correlating detection, containment, quarantine, recovery, reconciliation, and final verification without reducing an incident to raw logs or a reassuring status label.

## Lifecycle

The source contract supports:

`open → investigating → containment_pending → contained → recovery_pending → recovering → verification_pending → resolved → archived`

Not every incident requires every optional branch. However, every transition requires evidence, and the state may only advance through explicitly allowed transitions.

`contained` is an evidence claim, not an administrative label. It requires a normalized `protection_action` or `quarantine` event whose execution state is `verified`; policy evidence, an authorization, a request, transport delivery, or reconciliation metadata by itself cannot establish containment.

## Evidence and uncertainty

The timeline keeps normalized security events with producer identity, authority domain, observation time, evidence references, source-record references, and an explicit execution state.

Security-sensitive actions distinguish `requested`, `executing`, `verified`, `failed`, and `uncertain`. A request or transport acknowledgement is not successful execution.

Every `uncertain` event must carry durable source-record identity. The incident exposes `open_reconciliation_refs` so outstanding uncertain executions remain individually attributable rather than collapsing into one boolean. A verified reconciliation must bind one or more currently unresolved source records and clears only those matches. Unrelated uncertainty remains open and continues to block stronger incident states such as `contained`, `verification_pending`, or `resolved`.

Reconciliation resolves uncertainty about an execution record; it does not by itself manufacture a verified containment effect. After reconciliation, authoritative containment readback must still be represented as a verified protection or quarantine event before the incident can enter `contained`.

## Recovery boundary

Everkeep remains recovery authority. Wardveil may link an incident to Everkeep recovery evidence, but recovery evidence alone does not establish a Wardveil security-safe result.

When an incident is recovery-linked:

- a concrete recovery reference is required before entering `recovering`;
- Everkeep recovery evidence is required before final resolution;
- Wardveil must independently record recovery-security verification;
- only then can explicit resolution evidence support `resolved`.

## Resolution

`resolved` is never inferred from inactivity or the absence of new findings. It requires:

- explicit resolution evidence;
- a bounded final outcome;
- no open execution reconciliation;
- and, when recovery was involved, both Everkeep recovery evidence and independent Wardveil recovery verification.

The source model writes a normalized `resolution` timeline event when resolution succeeds so Security Center consumers can explain the incident through the same evidence-bearing timeline rather than relying only on a terminal state field.

Archived incident timelines are immutable in the reference model.

## Foundation compatibility

This next-upgrade incident contract is additive. It does not replace the Foundation 0.9 `reference/wardveil_incident.py` Quarantine, Audit, and Response reference layer or silently reinterpret its accepted runtime records. Migration or production acceptance of a next-upgrade Incident Plane requires separate runtime evidence and explicit consumer acceptance.

## Privacy and authority

The contract stores privacy-minimized references and summaries, not raw file contents, message bodies, credentials, secrets, tokens, or unrestricted diagnostics. Producer authority is recorded per timeline event. Mesh transport, Identity authentication, Everkeep recovery, or target acknowledgements do not transfer Wardveil security authority.

## Acceptance boundary

This is source-level next-upgrade work only. It does not provide durable production storage, live event ingestion, Security Center views, runtime deployment, production Quarantine execution, production Identity/key acceptance, Privacy Shield acceptance, Everkeep production acceptance, or Stable qualification.
