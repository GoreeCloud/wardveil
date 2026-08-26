# Wardveil Quarantine, Audit, and Response Reference Layer

Wardveil Foundation 0.8 includes a dependency-free reference implementation for the incident-control portion of the security plane.

## Quarantine

Wardveil Quarantine isolates a resource for review. Quarantine is not deletion. A newly quarantined resource begins in `pending` review state and requires explicit executor authority for review, release, or removal. Removal is modeled as a separate destructive action and must never be inferred from quarantine alone.

Every quarantine record must preserve represented scope, source security records, reason, evidence references, correlation identity, and authoritative producer identity.

## Audit

Wardveil Audit records security-relevant actions and outcomes. The reference layer uses a hash-linked event chain so accidental or unauthorized record mutation can be detected by conformance tooling. Hash chaining is an integrity aid, not a substitute for production-grade append-only storage, signatures, protected retention, access control, clock assurance, or external verification.

Audit events preserve actor identity, represented resource scope, correlation identity, evidence references, event type, and outcome. Secrets, credentials, recovery material, and unnecessary raw private data must not be placed into audit records merely for convenience.

## Response

Wardveil Response coordinates incident state through:

`open -> contained -> remediating -> recovering -> verified -> closed`

Transitions move forward one state at a time and require explicit action authority. A state transition is evidence about Wardveil's incident workflow; it is not proof that an application-owned or infrastructure-owned control executed unless that authoritative system provides corresponding evidence.

## Everkeep Boundary

Wardveil may coordinate security recovery with Everkeep but does not become the resilience or recovery authority. When an incident depends on recovery, entry into `recovering` requires an explicit recovery request or equivalent recovery-authority evidence. Wardveil may not mark that recovery-dependent incident `verified` or `closed` until recovery verification is explicitly represented.

This preserves the intended lifecycle:

`Wardveil Detects -> Wardveil Contains -> Everkeep Recovers -> Wardveil Verifies`

## Acceptance Boundary

The reference implementation defines reusable semantics and executable conformance behavior. It does not itself isolate production files, delete content, revoke sessions, disable credentials, restore backups, modify infrastructure, or establish application-specific production acceptance. Those operations remain with explicitly authorized executors and authoritative owning systems.
