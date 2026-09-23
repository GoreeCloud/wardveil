# Wardveil Security Privacy Shield Status Consumer

## Purpose

This contract defines how Wardveil Security may present GoreeCloud Privacy Shield status without absorbing Privacy Shield's privacy authority, inventing security evidence, or collecting raw private activity.

Privacy Shield is the platform-wide GoreeCloud privacy and privacy-control identity. Wardveil Security is the separate platform-wide security and protection identity. A Wardveil surface may display minimized Privacy Shield status as contextual information inside a broader protection view, but that presentation does not transfer enforcement authority between the two systems.

## Source contract

Wardveil consumes only status records conforming to the canonical Privacy Shield producer-to-consumer contract owned by `GoreeCloud/privacy-shield` at `contracts/privacy-shield.status.schema.json`.

The Privacy Shield producer remains authoritative for:

- adapter identity and runtime authority;
- declared privacy capabilities;
- capability state;
- runtime acceptance requirements;
- production approval;
- generation time;
- the explicit privacy guarantees carried by the status record.

Wardveil must not infer missing Privacy Shield capabilities or promote a runtime's acceptance state.

## Producer-source provenance

Wardveil pins the Privacy Shield producer contract it has reviewed through `contracts/wardveil.privacy-shield.consumer-source-evidence.json`. The current source-evidence pin is Privacy Shield revision `541d21e79f1377b8fa8b9a98e77d8e7bada66587` and source tree `d3bd8a932b3d25d711d350070913568ee733f323`.

That evidence identifies the exact producer status schema, producer status validator, provider-production-acceptance gate, state/signing acceptance schemas, and the successful exact-revision Privacy Shield Validation run used for this Wardveil integration review. The reviewed producer source requires every future production provider acceptance to bind the exact approved provider-selection decision. It now contains one failed FoundationDB state-provider candidate evaluation and one draft OVHcloud KMS HSM signing-key candidate evaluation, with four reviewed evidence packages, four active non-authorizing `accepted-for-evaluation` review attestations, zero complete provider evaluations, zero approved provider selections, zero accepted production state-provider records, and zero accepted production signing-provider records. The FoundationDB evaluation passes durability, atomic transactions, multi-writer serializability, distributed topology, and backup/restore as provider capabilities but fails access-control isolation because ordinary cluster connectivity is not a user-level security boundary and experimental tenants are not accepted for production; deployment-dependent criteria remain pending and the current one-VPS topology remains a separate blocker. The OVHcloud evaluation passes digest-only signing and HSM-backed non-exportability as provider capabilities while all GoreeCloud-specific key-reference, lifecycle, producer-identity, audit, fail-closed verification, outage, recovery, access-control, and operational criteria remain pending; the proprietary-service exception/necessity decision plus separate cost/order authorization also remain open. The reviewed producer source now also includes a provider-neutral external access-control assessment contract that requires exact-provider/deployment evidence for boundary exclusivity, workload identity, least privilege, credential lifecycle, bypass prevention, fail-closed unauthorized access, administrative governance, privacy-safe audit, and production-grade controls. There are zero access-control assessment records, so this gate changes no candidate result and creates no provider selection or production acceptance. The reviewed producer source now also rejects future-dated assessment timestamps, requires each governed assessment filename to match its `assessment_id`, and rejects duplicate assessment identifiers across governed records. Privacy Shield Validation run 35793080403 (#514) passed on the exact pinned main revision. At this revision all 17 other pinned source/provenance blobs remain byte-identical to the prior reviewed pin; the pinned validation-workflow blob changed to `57a611143ab91422ef3c9445a88969f447515d54`. The producer has also integrated source-only Policy and Observability contracts, which do not expand Wardveil's read-only status authority or establish accepted runtime coverage.

Source evidence does not establish runtime acceptance. Provider production acceptance remains unaccepted. A future Privacy Shield source revision, status-contract revision, provider-acceptance change, or validation change must be independently reviewed and repinned before Wardveil may treat it as the current reviewed producer boundary.

For any shared interaction that goes beyond read-only presentation, Wardveil still requires separately governed Privacy Shield runtime acceptance, deployed Identity/authenticated transport acceptance, target-environment evidence, and independent Wardveil runtime acceptance. Producer-source evidence alone never authorizes execution, aggregation into Wardveil required-control protection, production acceptance, or a `Protected by Wardveil` claim.

## Runtime acceptance boundary

Wardveil now defines a separate fail-closed shared-interaction runtime boundary in `contracts/wardveil.privacy-shield.runtime-acceptance.json`, with record structure defined by `contracts/wardveil.privacy-shield.runtime-acceptance.schema.json`.

This boundary is deliberately stronger than source provenance or status presentation. A future accepted shared interaction must bind exact Privacy Shield and Wardveil source revisions and trees, the exact minimized Privacy Shield status-record digest, authenticated and encrypted transport backed by GoreeCloud Identity, target-environment evidence, privacy-minimization evidence, a genuinely production-approved Privacy Shield runtime, and independent Wardveil consumer acceptance. Evidence must be content-addressed and freshness-bounded.

The shared-interaction record is still non-authorizing. It must set `authorization_effect=false`, `authority_transfer=false`, `protected_by_wardveil=false`, and `production_approved=false`. It cannot authorize target execution, cannot transfer Privacy Shield authority into Wardveil, cannot establish overall Wardveil production acceptance, and cannot create a `Protected by Wardveil` claim.

There are currently no records under `acceptance/privacy-shield/`. Source validation does not establish runtime acceptance. The current contract remains `production_runtime_status=unaccepted` until real producer-provider acceptance, deployed Identity-authenticated transport, target-environment evidence, and independent Wardveil runtime evidence are collected and accepted.

## Privacy boundary

A Privacy Shield record is eligible for Wardveil presentation only when it explicitly declares all of the following:

- `raw_private_activity_included` is `false`;
- `contains_credentials` is `false`;
- `contains_identifiers` is `false`;
- `runtime_acceptance_required` is `true`.

If any required guarantee is absent, malformed, or weakened, Wardveil must reject the record for normal presentation and treat the source as unknown/unavailable rather than attempting partial interpretation.

Wardveil must not request browsing history, visited URLs, search queries, DNS queries, network flows, cookies, request bodies, authentication headers, passwords, tokens, private keys, setup keys, recovery information, user identifiers, device identifiers, tracker-learning evidence, per-site exception contents, or raw application telemetry merely to populate a Privacy Shield summary.

## Full-record validation

Wardveil validates the complete Privacy Shield status record before applying any presentation mapping. Validation is fail-closed and preserves Privacy Shield as the producer authority rather than normalizing or repairing producer data.

The consumer rejects the record to `unknown` when the record is malformed, contains unsupported properties, uses an invalid producer or runtime-authority identifier, duplicates capability identifiers, weakens the required privacy exclusions, removes `runtime_acceptance_required`, omits required bounded validity for a protected or production-approved state, is expired at observation time, or is future-dated relative to the observation used for the decision.

Wardveil does not trim, rewrite, infer, or silently canonicalize Privacy Shield identifiers or timestamps. An invalid record must be corrected by the authoritative producer and reissued.

## Presentation mapping

Privacy Shield and Wardveil intentionally use different state vocabularies. Wardveil may map a sanitized Privacy Shield status to its presentation vocabulary only with the following conservative rules:

| Privacy Shield state | Wardveil presentation | Rationale |
| --- | --- | --- |
| `protected` | `protected` only when `production_approved=true`; otherwise `unknown` | A protection presentation must not outrun runtime acceptance. |
| `partial` | `attention` | Protection is incomplete and should remain visible for review. |
| `attention` | `attention` | The source already reports that review or action is needed. |
| `unavailable` | `unknown` | Missing status is not passing evidence. |
| `development` | `unknown` | Development state is not accepted protection evidence. |

A Privacy Shield record mapped to Wardveil `protected` still does **not** authorize `claim.protected_by_wardveil=true`. Privacy Shield remains the authority for the privacy capability. Wardveil is presenting the source state, not claiming that Wardveil itself enforced that privacy protection.

## Aggregation boundary

Privacy Shield status is informational security-context evidence and is excluded from Wardveil's primary required-control protection aggregation by default.

A product may show Privacy Shield beside Wardveil security controls, but it must not make a `Protected by Wardveil` claim more favorable because Privacy Shield is protected, and it must not make Privacy Shield appear to be a Wardveil-owned enforcement module.

If a future product needs Privacy Shield to participate in a specific composite posture decision, that scope and requirement must be explicitly defined in that product's own integration contract before aggregation. Availability alone is not authorization to aggregate.

## Provenance

A Wardveil presentation must preserve enough source attribution to identify Privacy Shield and the authoritative runtime producer. The minimum useful presentation is:

- Privacy Shield product identity;
- producer runtime authority;
- generation timestamp;
- normalized high-level state;
- declared capability states;
- production-approval state;
- an explicit statement that Wardveil is a read-only presenter of the record.

The Wardveil icon or `Protected by Wardveil` label must not replace the canonical Privacy Shield identity when the displayed information is specifically Privacy Shield state.

## Failure behavior

Wardveil fails closed for Privacy Shield presentation when:

- the status object is malformed;
- the schema version is unsupported;
- producer identity or runtime authority is missing;
- required privacy guarantees are missing or unsafe;
- runtime acceptance is not explicitly required;
- production approval is not a boolean;
- state is unsupported;
- capabilities are malformed or duplicated.

Failure produces `unknown`, never `protected`.

## Reference validation

`contracts/wardveil.privacy-shield.vectors.json` records the canonical mapping cases. `scripts/validate_wardveil_privacy_shield.py` validates those mappings and the privacy/authority invariants without importing or duplicating Privacy Shield runtime logic.

This is a presentation interoperability contract only. It does not create a Privacy Shield runtime inside Wardveil Security.
