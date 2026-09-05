# Wardveil Security — GoreeCloud Mesh Evidence Boundary

Wardveil Security can publish bounded, producer-authoritative security evidence through GoreeCloud Mesh using the GoreeCloud Evidence Envelope v1.

The source profile is `contracts/wardveil.mesh-evidence-profile.json`. The transport envelope is owned by GoreeCloud Mesh at `GoreeCloud/goreecloud-mesh/contracts/mesh.evidence-envelope.schema.json`.

## Pinned Mesh source compatibility

Wardveil's source profile pins both the Mesh evidence-envelope contract and the platform evidence-plane contract to the exact reviewed GoreeCloud Mesh revision `1002c74a2f014b04719b6809da22b0026546f8f0`.

The dedicated `Validate pinned Wardveil Mesh evidence contract source` workflow resolves that immutable revision from the Wardveil profile, checks out that exact Mesh source revision into a separate read-only contract source tree, verifies the checkout identity, and validates the Mesh envelope and platform evidence-plane invariants Wardveil relies on. The validation fails closed on contract, producer-authority, assertion-to-producer binding, minimization, transport-safety, or acceptance-boundary drift.

The pin is a source-compatibility record, not a claim that the pinned Mesh revision is deployed or production-accepted. Updating the pin creates a new Wardveil source candidate and requires exact-head validation again. Runtime delivery, deployed authorization, persistence, TLS/network behavior, production credentials, and production acceptance remain separate evidence gates.

## Authority separation

Wardveil remains authoritative for Wardveil-native security truth. Mesh provides coordination, provenance validation, freshness handling, discovery, and transport; it does not become a security authority.

A valid Mesh envelope therefore proves only that the transport record satisfies the Mesh envelope contract. Consumers must still evaluate the Wardveil producer contract governing the assertion.

Privacy Shield and Everkeep evidence retain their own authority. Wardveil may consume their bounded evidence when needed for security decisions, but must not re-label a Privacy Shield privacy decision or Everkeep recovery verification as Wardveil-authored source truth.

## Permitted versus producer-bound assertion families

The profile vocabulary includes these bounded transport families:

- security status;
- runtime acceptance;
- trust evaluations;
- policy decisions;
- protection results;
- detection findings;
- scan findings;
- quarantine state;
- incident state;
- response state; and
- security audit state.

**Permission in the transport vocabulary is not sufficient for publication.** Every family now has an explicit `producer_bindings` entry in the source profile. A family is publishable only when that entry is `status: bound` and the source adapter enforces the named canonical producer contract, record type where applicable, outcome field, and producer-declared validity field.

### Security-status binding

`security-status` is a strict producer-status path. `reference/wardveil_mesh_evidence.py` accepts it only from a closed `contracts/wardveil.status.schema.json` record with Wardveil Security authority, current unexpired producer evidence, the status contract's claim invariants, and its privacy/minimization shape.

The Mesh envelope outcome is derived from the canonical status record's `state`. A caller cannot turn a runtime policy record into `security-status`, override `attention` to `protected`, retain a protected claim on a non-protected state, or emit stale/non-authoritative status as current Mesh evidence. A `protected` envelope therefore requires the producer record itself to satisfy Wardveil's protected/current/authoritative contract before transport.

The envelope observation and validity timestamps are derived from the status record's evidence. Mesh may later regard retained evidence as stale after that producer-declared validity window passes; transport or retention does not renew Wardveil's protection claim.

### Runtime-record bindings

The currently bound generic runtime families use `contracts/wardveil.runtime.schema.json` and are exact assertion-to-record mappings:

- `trust-evaluation` → `trust_decision.trust_state`;
- `policy-decision` → `policy_decision.policy_decision`;
- `protection-result` → `protection_action.execution_status`;
- `detection-finding` → `detection_finding.detection_disposition`;
- `scan-finding` → `scan_finding.scan_result`;
- `quarantine-state` → `quarantine_record.review_state`;
- `incident-state` → `incident_record.incident_status`; and
- `security-audit-state` → `audit_event.outcome`.

The adapter validates runtime identity, producer authority, scope, observation/validity window, evidence references, and record-type-required state. The envelope outcome must equal the producer record's bound outcome field. An unrelated runtime record cannot be relabeled into another assertion family merely because it carries an additional compatible field.

### Explicitly unbound families

`runtime-acceptance` remains fail closed. Wardveil has a canonical Cloudflare acceptance-evidence model and an `acceptance_status`, but the current manifest contract does **not** provide a canonical producer-declared `valid_until`. Mesh Evidence Envelope v1 requires `valid_until`, and Wardveil must not invent a validity window merely to make the manifest transportable. If the producer acceptance model later gains a governed validity rule, that change requires separate source review and regression evidence before this binding may become active.

`response-state` also remains fail closed because no canonical Wardveil Response service producer record type with bound outcome and validity semantics is established. `reference/wardveil_mesh_refresh_response.py` is Mesh refresh coordination; it is not evidence of Wardveil Response service security state and must never be relabeled as such.

## Evidence minimization

Wardveil Mesh envelopes must not contain raw scan payloads, message bodies, file bodies, credentials, keys, tokens, secrets, or raw private user content.

Preferred envelope content is limited to bounded reason codes, derived state, canonical producer/revision/contract provenance, timestamps, opaque evidence references, and optional SHA-256 digests.

This preserves Wardveil's existing evidence-first model without turning Mesh into an unrestricted security telemetry store.

## Freshness

Wardveil is responsible for declaring `observed_at` and `valid_until` according to the assertion's own policy and runtime semantics. The producer adapter fails closed on future-dated or expired evidence and does not invent a universal Wardveil freshness window. Mesh and consumers may preserve expired evidence as historical transport state only where their own contracts permit it; they must not upgrade it back into current Wardveil security truth.

## Runtime acceptance

This profile is a source-level integration contract. It does not itself establish runtime acceptance, Cloudflare deployment acceptance, Security Center acceptance, Manager acceptance, or any product-specific production gate.
