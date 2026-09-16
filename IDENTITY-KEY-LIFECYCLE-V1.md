# Wardveil — GoreeCloud Identity and Key Lifecycle v1

**Status:** Development candidate  
**Work package:** G — Identity and Key Lifecycle  
**Authority boundary:** GoreeCloud Identity remains the identity, credential, service-identity, and signing-key authority. Wardveil is a bounded consumer of verified Identity evidence.

## Purpose

This package establishes a fail-closed Wardveil acceptance boundary for service identity and signing-key lifecycle evidence. It does not create a second credential issuer inside Wardveil and does not turn possession of a token, successful transport, a decoded JWT, or a caller assertion into Identity authority.

Wardveil must never claim more protection than GoreeCloud can prove.

## Pinned Identity credential-profile source reference

For the exact `goreecloud-identity.mesh-service-token.v1` credential-profile semantics consumed by this Wardveil package, the pinned source reference is GoreeCloud Identity draft PR #8 at exact revision `4ce7d193ff251ce3e7c39b8a19712317dd013c5d`.

This pin is deliberately narrow. It identifies the reviewed source contract for this Mesh credential profile; it does not make PR #8 the global authority for all current GoreeCloud Identity development, supersede the canonical `Project Specification — Identity`, resolve other active Identity review branches, or establish Identity production acceptance.

That revision publishes `goreecloud-identity.mesh-service-token.v1` schema version `1.3.0` with these source-level semantics:

- issuer `goreecloud-identity`;
- audience `goreecloud-mesh`;
- RS256 JWTs;
- minimum 2048-bit RSA keys;
- odd RSA public exponent greater than or equal to 3;
- required 8–128 character `kid` using `[A-Za-z0-9._-]`;
- verification through `application/json` JWKS;
- 300-second default and 900-second maximum lifetime;
- 60-second clock-skew bound;
- required `iss`, `aud`, `sub`, `service_id`, `scope`, `iat`, `exp`, and `jti` semantics, with optional `nbf`;
- rejection of token-selected or embedded verification-key sources such as `jku`, `jwk`, `x5u`, and `x5c`;
- private signing keys remaining inside GoreeCloud Identity;
- new signing keys published to JWKS before credentials using them are issued;
- fail-closed signature, protected-header, issuer, audience, expiry, not-before, service-identity, scope, key-ID, key-strength, and key-material verification.

The pinned Identity revision has successful dedicated GoreeCloud Mesh Service Token and GoreeCloud Identity Evidence Contract workflow results for its bounded credential-profile scope. Identity PR #8 remains draft and unmerged. Other active Identity development lines may carry different broader project changes or contract versions, so Wardveil must not generalize this pin beyond the exact credential profile evaluated here. Those boundaries prevent any claim of completed Identity production acceptance.

## Exact evidence-string binding

Authority-bearing Identity evidence is matched exactly rather than normalized into an acceptable value. The Wardveil evaluator rejects leading or trailing whitespace on the Identity authority, credential profile, exact Identity revision, usage, represented service ID, intended audience, algorithm, issuer, credential audience, `kid`, credential service ID, JWKS media type, and every required scope. A padded or tab-prefixed value is malformed evidence, not an equivalent spelling of an accepted authority value.

This rule prevents transport, parser, or producer differences from silently changing the bytes Wardveil treats as authoritative. Canonicalization, if required by a future Identity contract, must be explicitly defined and verified by GoreeCloud Identity before Wardveil adopts it; Wardveil must not invent normalization locally.

## Audience separation

The published Mesh profile is a credential for the `goreecloud-mesh` audience. Wardveil may use it only where Wardveil is acting as a GoreeCloud Mesh service producer/consumer under an approved Mesh integration.

A Mesh service token is **not** direct Wardveil execution authorization. Wardveil must reject any attempt to treat `goreecloud-identity.mesh-service-token.v1` as authority for a direct Wardveil action merely because the token is otherwise valid.

Any future direct Wardveil service-credential profile must be defined and approved by GoreeCloud Identity with its own exact intended audience, scopes, issuer/key contract, verification requirements, and acceptance evidence. Wardveil must not infer that profile locally.

## Wardveil acceptance model

`reference/wardveil_identity_key_lifecycle_v1.py` evaluates bounded evidence produced by an approved GoreeCloud Identity verifier. The reference evaluator is intentionally not a cryptographic verifier and is not an issuer.

For the current Mesh profile it requires, at minimum:

- exact GoreeCloud Identity authority;
- the reviewed exact Identity credential-profile source revision;
- source-validated credential profile evidence;
- exact RS256 / issuer / audience profile matching;
- exact canonical service, audience, profile, and scope strings without silent surrounding-whitespace normalization;
- bounded lifetime;
- canonical GoreeCloud service identity binding;
- verified signature and protected header;
- verified issuer and audience;
- verified time validity;
- verified workload identity and required scope;
- resolved `kid` and non-revoked verification key;
- trusted JWKS transport;
- acceptable RSA key strength and public exponent;
- `application/json` JWKS media type.

Any missing, malformed, padded, normalized, or contradictory required evidence fails closed.

## Production gates

Source-valid credential semantics are not production identity acceptance. Wardveil production acceptance remains false unless authoritative evidence establishes every applicable gate:

- GoreeCloud Identity production acceptance for the exact service-credential path;
- live credential issuance deployment;
- deployed trusted JWKS delivery;
- durable protected private-signing-key custody;
- tested key rotation;
- tested credential revocation;
- tested replay protection;
- tested expiration enforcement;
- auditable key/identity use without exposing secrets;
- tested emergency key/credential revocation procedures;
- Wardveil runtime validation against the exact accepted Identity path.

Reference-only key files, local development keys, source tests, passing transport, or a successful policy decision cannot satisfy these production gates by themselves.

## Claim authority

The reference model exposes `claim_authority=true` only when the exact credential evidence is accepted and all production gates are explicitly satisfied for the evaluated path. Current repository work must not interpret that theoretical evaluator outcome as evidence that those external production gates have already been completed.

The current Work Package G implementation is source-level development work only. It does not deploy GoreeCloud Identity, deploy JWKS, provision production signing keys, rotate or revoke a production key, migrate Wardveil runtime authentication, or establish production acceptance.

## Secret handling

Wardveil evidence must not contain private signing keys, bearer credentials, client secrets, passwords, recovery secrets, session secrets, or other reusable authentication material. Durable evidence should carry only the minimum provenance required to explain which Identity authority/profile/key identifier and verification outcome governed an operation.

## Exit criterion

Work Package G can exit source implementation only after the contract, evaluator, tests, validator, CI integration, roadmap status, and canonical project documentation agree on this boundary.

Production acceptance remains a separate gate. The package is not production-complete until reference-only authorization or cryptographic mechanisms are absent from every production-accepted Wardveil execution path and the authoritative GoreeCloud Identity/key lifecycle evidence proves the live path.
