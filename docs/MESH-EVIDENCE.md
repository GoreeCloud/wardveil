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

**Permission in the transport vocabulary is not sufficient for publication.** Every family has an explicit `producer_bindings` entry in the source profile. A family is publishable only when that entry is `status: bound` and the applicable source adapter enforces the named canonical producer contract, record type where applicable, outcome field, and producer-declared validity field.

### Security-status binding

`security-status` is a strict producer-status path. `reference/wardveil_mesh_evidence.py` accepts it only from a closed `contracts/wardveil.status.schema.json` record with Wardveil Security authority, current unexpired producer evidence, the status contract's claim invariants, and its privacy/minimization shape.

The Mesh envelope outcome is derived from the canonical status record's `state`. A caller cannot turn a runtime policy record into `security-status`, override `attention` to `protected`, retain a protected claim on a non-protected state, or emit stale/non-authoritative status as current Mesh evidence. A `protected` envelope therefore requires the producer record itself to satisfy Wardveil's protected/current/authoritative contract before transport.

The envelope observation and validity timestamps are derived from the status record's evidence. Mesh may later regard retained evidence as stale after that producer-declared validity window passes; transport or retention does not renew Wardveil's protection claim.

### Runtime-acceptance binding

`runtime-acceptance` is a separate producer path rather than a generic runtime record. `reference/wardveil_mesh_runtime_acceptance.py` accepts only a closed `contracts/wardveil.cloudflare.acceptance-evidence.schema.json` manifest for the Wardveil Cloudflare persistence runtime.

The source policy in `contracts/wardveil.cloudflare.runtime-acceptance.json` defines `evidence_validity_seconds: 3600`. A live manifest must therefore carry `valid_until` exactly one hour after `collected_at`. The dedicated adapter verifies that producer-declared deadline and preserves it unchanged in the Mesh envelope. Missing, future-dated, non-canonical, placeholder-revision, or expired evidence fails closed.

The Mesh outcome is derived exclusively from the manifest's `acceptance_status`. An `accepted` manifest is valid only when every canonical acceptance check is `passed`; a caller cannot substitute an outcome. The adapter emits only minimized state, immutable revision/contract provenance, timestamps, a bounded source reference, and a digest of the complete producer manifest.

This binding does **not** make the generic Wardveil runtime-record adapter accept `runtime-acceptance`. Policy decisions, protection actions, findings, quarantine records, incidents, or audit events cannot be relabeled as infrastructure acceptance evidence.

Runtime acceptance remains infrastructure acceptance only. It is not `Protected by Wardveil`, trust, authorization, malware cleanliness, incident closure, restore verification, or broad Wardveil production acceptance. The source-controlled production template remains expired, placeholder-revision, and `unaccepted`.

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

The validated runtime `producer.id` is preserved through the producer-controlled opaque `source` reference as `wardveil://producers/<percent-encoded-producer-id>/records/<percent-encoded-record-id>`. Reserved URI characters are encoded so producer and record identity cannot escape the reference structure. The complete runtime record, including its producer object, remains covered by the envelope payload digest.

This preservation is provenance, **not authentication**. The Mesh transport producer remains `wardveil-security`; GoreeCloud Identity and the authenticated Mesh delivery path remain authoritative for service/delivery authentication. A source reference containing a producer ID must never be treated as proof that the producer was authenticated.

### Explicitly unbound family

`response-state` remains fail closed because no canonical Wardveil Response service producer record type with bound outcome and validity semantics is established. `reference/wardveil_mesh_refresh_response.py` is Mesh refresh coordination; it is not evidence of Wardveil Response service security state and must never be relabeled as such.

## Evidence minimization

Wardveil Mesh envelopes must not contain raw scan payloads, message bodies, file bodies, credentials, keys, tokens, secrets, or raw private user content.

Preferred envelope content is limited to bounded reason codes, derived state, canonical producer/revision/contract provenance, timestamps, opaque evidence references, and optional SHA-256 digests.

This preserves Wardveil's existing evidence-first model without turning Mesh into an unrestricted security telemetry store.

## Freshness

Wardveil is responsible for declaring `observed_at` and `valid_until` according to each assertion's own policy and runtime semantics. Generic runtime records use their producer-declared validity, status evidence uses its status evidence deadline, and Cloudflare runtime acceptance uses the governed one-hour acceptance window.

Adapters fail closed on future-dated or expired evidence. Mesh and consumers may preserve expired evidence as historical transport state only where their own contracts permit it; they must not upgrade it back into current Wardveil security truth or extend producer validity locally.

## Runtime acceptance boundary

This profile is a source-level integration contract. Binding the `runtime-acceptance` assertion means only that current producer-authoritative acceptance manifests now have a valid Mesh representation. It does not itself establish Cloudflare deployment acceptance, Security Center acceptance, Manager acceptance, broad Wardveil production acceptance, or any product-specific production gate.
