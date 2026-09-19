# Wardveil Audit and Evidence Ledger — Next-Upgrade Source Contract

**Status:** Development / Source Candidate  
**Contract:** `urn:goreecloud:wardveil:audit-event:0.1.0`

The next-upgrade Wardveil Audit and Evidence Ledger gives high-impact Wardveil decisions and actions a first-class, privacy-minimized provenance record. It is designed so Security Center and authorized operators can explain what was requested, who or what acted, what authority and evidence were involved, what actually happened, whether uncertainty remains, and what later reconciliation proved.

## Provenance contract

Each audit event has bounded fields for correlation, producer identity and authority domain, acting identity, policy/authorization/executor/signing-key identity where applicable, target authority and resource scope, requested action, evidence and source-record references, execution outcome, reconciliation state, incident/quarantine links, observation time, evidence validity, reason code, summary, retention metadata, and integrity-chain hashes.

Producer identity and acting identity are separate. A service that writes an audit record does not thereby acquire authority over the target resource.

Authorization is not execution success. An execution event recorded as `succeeded` requires separate verification evidence. An authorization ID, policy decision, request, transport acknowledgement, executor start, persistence write, or Security Center rendering cannot satisfy that requirement by itself.

## Append-only integrity

The reference ledger is append-only through its public interface. Events use monotonically increasing sequence numbers and SHA-256 links to the previous event so mutation or reordering becomes detectable in the conformance model.

This hash chain is integrity evidence for the reference model. It is not a production signing, notarization, transparency-log, or key-management system.

## Execution uncertainty and reconciliation

An execution whose outcome is unknown must be recorded with `reconciliation_state=required`. Each uncertain execution remains individually addressable by its audit-event ID.

Reconciliation is a new event. It never rewrites the original execution record. A reconciliation event must bind a currently open uncertain audit event and produce one of `succeeded`, `failed`, `not_executed`, or `unknown`.

An `unknown` reconciliation keeps the original uncertainty open. A verified non-unknown reconciliation closes only the matching uncertain execution. It cannot silently clear another action, manufacture a new authorization, or cause blind re-execution.

## Evidence freshness

Audit is historical provenance, not current security state. The event preserves the evidence observation time and, when the producer supplied one, its validity deadline.

Expired evidence may remain historical so an authorized reviewer can understand why an earlier decision was made. Expiration must not be hidden, and historical evidence must not be reused to manufacture current protection, authorization, cleanliness, containment, recovery, or `Protected by Wardveil` state.

## Privacy and retention

Privacy Shield remains the privacy and minimization authority.

The contract deliberately has no arbitrary raw-payload or unrestricted metadata field. It records bounded identifiers, references, reason codes, summaries, and evidence links rather than file contents, message bodies, credentials, reusable tokens, private keys, or unrestricted diagnostics. The reference layer also rejects common obvious credential markers in bounded textual fields.

Audit reference fields are logical identifiers, not transport URLs. `evidence_refs`, `verification_evidence_refs`, `source_record_refs`, `incident_ref`, and `quarantine_object_ref` use a bounded credential-safe logical-reference grammar that supports colon-delimited namespaces and slash-delimited logical paths, including content-addressed forms such as `evidence+sha256:<digest>:reports/verification.json`. Transport delimiters and common credential-bearing syntax—including `://`, query strings, fragments, user-info markers, percent-encoded material, assignment/parameter delimiters, backslashes, and whitespace—are rejected. Retrieval credentials, signed URLs, bearer material, and similar access secrets must remain outside durable audit records.

This reference rule does not convert audit-event IDs, correlation IDs, authorization IDs, or other record identities into evidence locators. Those identities remain distinct from the logical references that point to evidence or source records.

Audit events use the established `audit_evidence` retention class, with the existing Wardveil reference retention baseline of 365 days. Each event records purpose `security_provenance`, access authority `wardveil-audit`, expiry, and `may_leave_origin=false`.

This source policy does not override a stricter Privacy Shield requirement, legal requirement, incident-preservation requirement, or approved environment-specific retention policy. Production retention enforcement and authorized export remain separate acceptance work.

## Security Center explanation boundary

The reference ledger can produce a bounded explanation view containing the producer, acting identity, target, requested action, outcome, evidence freshness, reconciliation state, evidence references, incident/quarantine links, reason code, and summary.

Security Center should use structured provenance to answer “Why this status?” rather than requiring users to interpret raw logs. The explanation is not itself security authority and cannot upgrade the underlying evidence.

## Foundation compatibility

Foundation 0.9 already has a basic hash-linked `AuditEvent` primitive in `reference/wardveil_incident.py`. This next-upgrade contract is additive and strengthens provenance, execution verification, reconciliation, evidence-freshness, retention, and privacy semantics without silently reinterpreting accepted Foundation 0.9 runtime records.

Migration requires explicit producer and consumer acceptance.

## Acceptance boundary

This is source-level next-upgrade work only. Production durable storage remains unaccepted. The reference ledger is in-memory and does not establish production persistence, tamper-resistant external anchoring, production cryptographic signing, deployed producer ingestion, Security Center live consumption, production retention enforcement, production Identity/key acceptance, Privacy Shield runtime acceptance, Everkeep recovery acceptance, Stable qualification, or a broad `Protected by Wardveil` claim.
