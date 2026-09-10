# Wardveil Incident Plane — Next-Upgrade Source Contract

**Status:** Development / Source Candidate  
**Contract:** `urn:goreecloud:wardveil:incident:0.1.0`

The next-upgrade Incident Plane gives Wardveil a first-class, evidence-driven incident record for correlating detection, containment, quarantine, recovery, reconciliation, and final verification without reducing an incident to raw logs or a reassuring status label.

## Lifecycle

The source contract supports:

`open → investigating → containment_pending → contained → recovery_pending → recovering → verification_pending → resolved → archived`

Not every incident requires every optional branch. However, every transition requires evidence, and the state may only advance through explicitly allowed transitions.

## Evidence and uncertainty

The timeline keeps normalized security events with producer identity, authority domain, observation time, evidence references, source-record references, and an explicit execution state.

Security-sensitive actions distinguish `requested`, `executing`, `verified`, `failed`, and `uncertain`. A request or transport acknowledgement is not successful execution. An `uncertain` action opens reconciliation and blocks stronger incident states such as `contained`, `verification_pending`, or `resolved` until authoritative reconciliation evidence closes the uncertainty.

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

Archived incident timelines are immutable in the reference model.

## Privacy and authority

The contract stores privacy-minimized references and summaries, not raw file contents, message bodies, credentials, secrets, tokens, or unrestricted diagnostics. Producer authority is recorded per timeline event. Mesh transport, Identity authentication, Everkeep recovery, or target acknowledgements do not transfer Wardveil security authority.

## Acceptance boundary

This is source-level next-upgrade work only. It does not provide durable production storage, live event ingestion, Security Center views, runtime deployment, production Quarantine execution, production Identity/key acceptance, Privacy Shield acceptance, Everkeep production acceptance, or Stable qualification.
