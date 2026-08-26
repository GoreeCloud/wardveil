# Wardveil Cross-Service Integration Pipeline

Wardveil Foundation 0.8 includes separate reference implementations for Trust, Policy, Protect, Detect, Scan, Quarantine, Response, Audit, and Security Center. This document defines a bounded in-process orchestration reference that composes those services without collapsing their authority boundaries.

## Goals

- Preserve one correlation ID across related Wardveil records.
- Demonstrate how authoritative Trust and Policy decisions feed Protect.
- Demonstrate how Detect and Scan findings can feed Quarantine and Response.
- Emit Audit records for material protection and quarantine actions.
- Feed the resulting authoritative records into the Security Center read model.
- Fail closed when required evidence, authority, or scan coverage is absent.

## Access flow

`Access request → Trust → Policy → Protect → Audit → Security Center`

Trust remains distinct from authorization. Policy intent remains distinct from execution. A successful protection status requires an actual succeeded Protect record, not a policy decision alone.

## Content-threat flow

`Content → Detect + Scan → Quarantine → Response → Audit → Security Center`

A material threat is limited to a likely/confirmed malicious Detect finding or a malicious Scan result. Suspicious/anomalous evidence alone does not automatically create a confirmed incident. Unknown or unsupported scan coverage remains degraded rather than clean.

## Correlation and evidence

Every record emitted by one pipeline invocation shares a correlation ID. Evidence references are preserved from authoritative inputs. When a reference path lacks an external evidence reference, source record identifiers may be used only as correlation evidence for the reference Audit event; this does not manufacture external technical evidence.

## Authority boundaries

The pipeline itself is not an enforcement authority. Protect still requires an explicit `ExecutorAuthority`. Quarantine still requires explicit quarantine authority. Production mutation remains with application- or infrastructure-specific executors. Everkeep remains authoritative for recovery. Privacy Shield remains authoritative for privacy and data-minimization decisions. GoreeCloud Mesh may later transport these records but does not gain authority to upgrade their security state or validity.

## Acceptance boundary

This integration layer is a dependency-free conformance reference and test harness. It does not establish production deployment, durable storage, message transport, application runtime acceptance, Stable qualification, or real malware/threat-intelligence capability. Those require separately evidenced product integrations.
