# Wardveil Security — GoreeCloud Mesh Evidence Boundary

Wardveil Security can publish bounded, producer-authoritative security evidence through GoreeCloud Mesh using the GoreeCloud Evidence Envelope v1.

The source profile is `contracts/wardveil.mesh-evidence-profile.json`. The transport envelope is owned by GoreeCloud Mesh at `GoreeCloud/goreecloud-mesh/contracts/mesh.evidence-envelope.schema.json`.

## Pinned Mesh source compatibility

Wardveil's source profile pins both the Mesh evidence-envelope contract and the platform evidence-plane contract to the exact reviewed GoreeCloud Mesh revision `1002c74a2f014b04719b6809da22b0026546f8f0`.

The dedicated `Validate pinned Wardveil Mesh evidence contract source` workflow resolves that immutable revision from the Wardveil profile, checks out that exact Mesh source revision into a separate read-only contract source tree, verifies the checkout identity, and validates the Mesh envelope and platform evidence-plane invariants Wardveil relies on. The validation fails closed on contract, producer-authority, minimization, transport-safety, or acceptance-boundary drift.

The pin is a source-compatibility record, not a claim that the pinned Mesh revision is deployed or production-accepted. Updating the pin creates a new Wardveil source candidate and requires exact-head validation again. Runtime delivery, deployed authorization, persistence, TLS/network behavior, production credentials, and production acceptance remain separate evidence gates.

## Authority separation

Wardveil remains authoritative for Wardveil-native security truth. Mesh provides coordination, provenance validation, freshness handling, discovery, and transport; it does not become a security authority.

A valid Mesh envelope therefore proves only that the transport record satisfies the Mesh envelope contract. Consumers must still evaluate the Wardveil producer contract governing the assertion.

Privacy Shield and Everkeep evidence retain their own authority. Wardveil may consume their bounded evidence when needed for security decisions, but must not re-label a Privacy Shield privacy decision or Everkeep recovery verification as Wardveil-authored source truth.

## Permitted Wardveil evidence families

The initial source profile permits bounded envelope publication for:

- security status;
- runtime acceptance;
- trust evaluations;
- policy decisions;
- protection results;
- detection findings;
- scan findings;
- quarantine state;
- incident and response state;
- security audit state.

These names describe transport families only. Their valid outcomes, scope, and acceptance rules remain defined by the applicable Wardveil contract.

### Security-status binding

`security-status` is a strict producer-status path. `reference/wardveil_mesh_evidence.py` accepts it only from a closed `contracts/wardveil.status.schema.json` record with Wardveil Security authority, current unexpired producer evidence, the status contract's claim invariants, and its privacy/minimization shape.

The Mesh envelope outcome is derived from the canonical status record's `state`. A caller cannot turn a runtime policy record into `security-status`, override `attention` to `protected`, retain a protected claim on a non-protected state, or emit stale/non-authoritative status as current Mesh evidence. A `protected` envelope therefore requires the producer record itself to satisfy Wardveil's protected/current/authoritative contract before transport.

The envelope observation and validity timestamps are derived from the status record's evidence. Mesh may later regard retained evidence as stale after that producer-declared validity window passes; transport or retention does not renew Wardveil's protection claim.

### Runtime-record binding

Non-status runtime assertion families use `contracts/wardveil.runtime.schema.json` rather than claiming the status contract. The reference adapter validates the runtime identity, producer authority, scope, observation/validity window, evidence references, and record-type-required state used to construct the minimized envelope. Where an assertion directly corresponds to a runtime outcome field, the envelope outcome must match the producer record rather than a caller override.

## Evidence minimization

Wardveil Mesh envelopes must not contain raw scan payloads, message bodies, file bodies, credentials, keys, tokens, secrets, or raw private user content.

Preferred envelope content is limited to bounded reason codes, derived state, canonical producer/revision/contract provenance, timestamps, opaque evidence references, and optional SHA-256 digests.

This preserves Wardveil's existing evidence-first model without turning Mesh into an unrestricted security telemetry store.

## Freshness

Wardveil is responsible for declaring `observed_at` and `valid_until` according to the assertion's own policy and runtime semantics. The producer adapter fails closed on future-dated or expired evidence and does not invent a universal Wardveil freshness window. Mesh and consumers may preserve expired evidence as historical transport state only where their own contracts permit it; they must not upgrade it back into current Wardveil security truth.

## Runtime acceptance

This profile is a source-level integration contract. It does not itself establish runtime acceptance, Cloudflare deployment acceptance, Security Center acceptance, Manager acceptance, or any product-specific production gate.
