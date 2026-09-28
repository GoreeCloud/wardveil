# Wardveil Incident Center V1

Status: **Development source foundation**. This source does not establish a production incident, containment authority, Protected/Covered status, deployed monitoring, or production acceptance.

## Purpose

Incident Center V1 provides a fail-closed review intake between Wardveil Detection Engine V1 and the existing Incident/Response authority layer. It converts fresh Detection Engine assessments that already carry `incident_candidate=true` into an explainable **incident review case** for one exact resource.

The review case is triage evidence only. It does not call `create_incident`, transition an incident, quarantine a resource, request recovery, or execute any response.

## Intake rules

- Inputs must be Wardveil Detection Engine V1 `DetectionAssessment` values.
- Inputs for different resources must be partitioned before review.
- Any input claiming execution authority is rejected.
- Only fresh, currently valid assessments with `incident_candidate=true` contribute to a review case.
- Candidate assessments must retain evidence references and supported Detection Engine severity/disposition values.
- Stale, future-dated, expired, or non-candidate assessments are excluded rather than promoted.
- If no fresh incident candidate remains, the review case is `unknown`.
- A fresh candidate produces only `review_required`; it never produces an established incident.

## Review priority

Review priority is derived only from the highest fresh candidate severity:

- informational/low → `routine`
- medium → `attention`
- high → `high`
- critical → `critical`

Priority is a triage presentation value, not execution authorization.

## Incident and response boundary

Every serialized case fixes:

- `incident_established=false`
- `execution_authority=false`
- `containment_authority=false`
- `production_accepted=false`

Creating or transitioning a real Wardveil incident remains governed by the existing Incident/Response authority path and its authorization, audit, target-state, reconciliation, recovery, and evidence requirements.

Production completion remains separately gated on approved runtime signal producers, authenticated delivery, durable incident operations, target-environment validation, privacy-minimized retention, recovery behavior, independent review, and production acceptance.
