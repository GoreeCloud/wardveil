# Wardveil Detection Engine V1

Status: **Development source foundation**. This source does not establish deployed monitoring, production coverage, containment authority, Protected/Covered status, or production acceptance.

## Purpose

Detection Engine V1 correlates fresh, authoritative behavioral security signals for one resource into an explainable assessment. It bridges lower-level Detect/Scan evidence toward the Incident Plane without turning correlation into execution authority.

Supported signal classes cover privilege changes, credential abuse indicators, suspicious process activity, rapid file changes, persistence indicators, unauthorized system modification, anomalous networking, sensitive-file access, abnormal background activity, administrative anomalies, rapid permission changes, and post-update behavior changes.

## Fail-closed rules

Each signal must include a stable identifier, supported category, exact resource identity, producer and authority domain, bounded severity/confidence, timezone-aware observation/validity timestamps, and evidence references.

Untrusted, stale, expired, or future-dated signals do not contribute to escalation. If no fresh authoritative evidence remains, the result is `unknown`. Conflicting reuse of a signal identifier fails closed. Different resources must be partitioned before correlation.

A result is correlated only when at least two distinct fresh authoritative categories and at least two evidence references support the same resource within the bounded correlation window.

## Incident and authority boundaries

`incident_candidate=true` means only that a separate Incident Plane review may be appropriate. It does not create an incident or execute a response.

Every serialized assessment fixes `execution_authority=false`. Any protection action still requires the applicable Policy decision, execution authorization, executor permission, target authority, durable reconciliation, and authoritative result readback.

Production completion remains separately gated on approved signal producers, authenticated transport, durable state where required, privacy-minimized operations, target-environment validation, recovery behavior, and independent production acceptance.
