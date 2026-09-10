# Wardveil Security — Feature Roadmap

**Status:** Active roadmap control  
**As of:** 2026-09-10  
**Authoritative project record:** Project Specification — Wardveil Security  
**Canonical repository:** GoreeCloud/goreecloud-wardveil-security
**Drive control:** `GoreeCloud/Feature Roadmap/Wardveil Security/FEATURE-ROADMAP.docx`

## Purpose

This file is the repository-side feature roadmap control for Wardveil Security. It records current planned and recommended feature work without replacing the authoritative project record, implementation evidence, release gates, or GoreeCloud Tasks Management.

## Roadmap

| ID | Feature / obligation | Priority | Current state |
| --- | --- | --- | --- |
| FR-001 | Reconcile and maintain every current planned or recommended Wardveil Security feature from the authoritative project record and verified repository evidence in this roadmap. | High | Ongoing control |
| FR-002 | Move actionable feature obligations into GoreeCloud Tasks Management when required, preserving priority, dependency, and lifecycle disposition. | High | Ongoing control |
| FR-003 | Do not mark features implemented, complete, cancelled, or superseded without authoritative evidence and synchronized repository/Drive roadmap updates. | High | Ongoing control |
| FR-004 | Develop the Wardveil next-upgrade security-state foundation, including evidence freshness, fail-closed protection claims, Foundation 0.9 compatibility, and exact-head validation. | High | Source Validated — Development candidate (PR #145; runtime and production acceptance pending) |
| FR-005 | Implement the machine-readable Protection Coverage Registry across application/service scope and capability, including Covered, Partial, Not Covered, Unknown, Stale, and Degraded states; enforcement-point coverage; evidence freshness; adoption lifecycle; conflict rejection; gap/remediation visibility; Stable impact; and exact-head validation. | High | Source Validated — Development candidate (PR #145; runtime integration, Security Center consumption, production acceptance, and Stable qualification pending) |
| FR-006 | Implement the durable next-upgrade Quarantine object and execution-reconciliation model, including non-destructive lifecycle states, separate authorization for quarantine/release/restore/remove/rescan/escalate/recover, destructive Delete separation, authoritative target-state verification, durable transition history, uncertain-outcome reconciliation, and no blind reuse of the original authorization. | High | Source Validated — Development candidate (PR #145; live target execution/readback, runtime validation, production acceptance, Security Center consumption, and Stable qualification pending) |
| FR-007 | Implement the next-upgrade Incident Plane with evidence-driven lifecycle transitions; normalized finding, detection, trust, policy, authorization, protection, quarantine, reconciliation, recovery, and resolution events; individually attributable unresolved execution state; verified containment requirements; Everkeep/Wardveil recovery boundaries; explicit resolution evidence; and an explainable Security Center-ready timeline. | High | Source Validated — Development candidate (PR #145; durable production storage, live event ingestion, runtime validation, Security Center live consumption, production recovery integration, production acceptance, and Stable qualification pending) |
| FR-008 | Implement the next-upgrade Audit and Evidence Ledger with privacy-minimized producer/actor/policy/authorization/executor/key/target provenance; verified execution outcomes; append-only integrity chaining; individually bound reconciliation; evidence freshness; explicit retention/purpose/access metadata; secret-exclusion safeguards; and a Security Center-ready explanation contract. | High | Source Validated — Development candidate (PR #145; production durable storage, producer ingestion, Security Center live consumption, retention enforcement, production Identity/key acceptance, Privacy Shield acceptance, production acceptance, and Stable qualification pending) |
| FR-009 | Implement Security Center 2.0 as the next-upgrade user/admin read model with the complete twelve-area information architecture; first-class Why this status? explanations; fail-closed Protected presentation; GLAZE UI V1.3 / 1.3.0 Stable targeting; Light, Dark, Deep Dark, responsive and accessibility modes; material/performance fallbacks; and explicit rendered-review, live-evidence, deployment, rollback, runtime, production, and Stable acceptance gates. | High | Source Validated — Development candidate (PR #145; active-site migration, rendered visual/accessibility review, live next-upgrade evidence consumption, deployment verification, rollback verification, runtime validation, production acceptance, and Stable qualification pending) |

## Maintenance and synchronization

This roadmap and the corresponding Drive `FEATURE-ROADMAP.docx` must remain materially synchronized with one another and with the authoritative project or service record. Update both copies whenever feature scope, priority, dependency, implementation status, cancellation, supersession, recommendation, or verification state materially changes.

No feature may be represented as complete or Stable solely because it appears in this roadmap. Completion and lifecycle claims require the applicable authoritative implementation, validation, review, release, and production evidence.

## Reconciliation rule

At each material feature change, reconcile this roadmap against the current authoritative project record, repository implementation state, applicable platform-system requirements, and GoreeCloud Tasks Management. Missing obligations, stale status, duplicated work, roadmap drift, or undocumented disposition changes are defects to correct.
