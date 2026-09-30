# Wardveil Security Architecture

Wardveil Security is GoreeCloud's platform-wide first-party security system. It combines shared security services, evidence-backed status, policy decisions, enforcement, detection, inspection, isolation, incident response, and user/admin security experiences behind one coherent security plane.

Wardveil is not a decorative badge and it is not a single monolithic application. GoreeCloud applications and services integrate with Wardveil through explicit contracts and remain responsible for supplying authoritative evidence for the controls they own.

## Canonical first-party capability model

| Capability | Primary responsibility | Typical inputs | Typical outputs |
| --- | --- | --- | --- |
| **Wardveil Trust** | Identity, session, device, service, and contextual risk evaluation | authentication strength, device integrity, session provenance, network/context changes, recent security events | trust state, risk reasons, verification requirements |
| **Wardveil Policy** | Central security policy evaluation and decision logic | trust state, requested operation, actor, resource, organizational policy, protection state | allow, deny, restrict, step-up, quarantine, escalation decisions |
| **Wardveil Protect** | Preventive controls and enforcement | policy decisions, protection configuration, threat findings, bound runtime authorization | enforced blocks, restrictions, step-up authentication, session/credential actions |
| **Wardveil Detect** | Threat, abuse, behavioral, and anomaly detection | security events, authentication activity, application telemetry, network signals | findings, confidence, severity, correlated threat signals |
| **Wardveil Scan** | File, content, package, URL, attachment, download, and payload inspection | files, messages, URLs, packages, supported payload metadata | clean/suspicious/malicious/unknown findings with evidence |
| **Wardveil Quarantine** | Isolation, containment, review, release, and remediation of unsafe or uncertain objects | scan/detection findings, policy decisions | isolated object state, review record, release/removal decision |
| **Wardveil Response** | Incident containment, remediation, escalation, and recovery coordination | confirmed incidents, correlated findings, policy triggers | containment actions, incident workflow, remediation tasks, recovery verification |
| **Wardveil Audit** | Security evidence, decision history, event history, and accountability | decisions, findings, enforcement actions, operator actions | immutable or tamper-evident audit records, evidence chains, reports |
| **Wardveil Security Center** | Unified user and administrator protection experience | normalized Wardveil states, findings, incidents, devices, policies, quarantine, audit summaries | understandable status, alerts, investigation, remediation, administration |

These names describe substantive first-party capabilities. A capability may be implemented as one service or several cooperating components, but its responsibility boundary must remain explicit.

## Security lifecycle

A representative flow is:

`Trust -> Policy -> Protect -> Detect -> Scan -> Quarantine -> Response -> Audit`

The flow is not strictly linear. Detect may invoke Scan; Scan may trigger Quarantine; Response may ask Trust to revoke or downgrade sessions; Policy may be reevaluated whenever evidence changes. Wardveil Audit receives material security decisions and actions throughout the lifecycle. Wardveil Security Center spans the lifecycle as the human-facing visibility and control layer.

## Architectural invariants

1. **Evidence before reassurance.** A protected state requires current authoritative evidence for the represented scope. Missing, stale, malformed, unavailable, or unverified required evidence fails closed.
2. **Explicit authority.** Wardveil does not invent the state of a control it does not own. Producers identify their authority and scope; Wardveil can normalize, correlate, decide, enforce, and present only within documented contracts.
3. **Least privilege.** Services receive only the data and capabilities required for the decision or action being performed.
4. **Data minimization.** Wardveil evidence must not become a secret store or a general telemetry lake. Reusable credentials, private keys, tokens, recovery material, raw private activity, and unnecessary personal data are prohibited from shared evidence records.
5. **Separation of decision and execution.** Policy decisions are explicit and auditable. High-impact cross-service actions require a bound runtime execution authorization, defined executor, idempotency behavior, replay resistance, and audit trail.
6. **Fail-closed mutation.** Security-changing actions must reject ambiguous targets, stale authorization, unsupported versions, missing evidence, invalid signatures, replay conflicts, and untrusted callers rather than guessing.
7. **Explainability.** Elevated-risk, restricted, quarantine, and incident states expose human-understandable reasons without leaking sensitive detection internals.
8. **Conservative aggregation.** A platform summary cannot be more favorable than the weakest required evidence in its represented scope.
9. **Platform separation.** Privacy Shield, Everkeep, Glaze UI, and GoreeCloud Mesh remain distinct systems with their own authority boundaries.
10. **Verifiable claims.** `Protected by Wardveil` is allowed only for an explicit scope backed by current evidence that Wardveil or a Wardveil-authorized producer actually enforced or verified.

## Trust and policy decision model

A Wardveil decision should carry at minimum:

- request/decision identifier;
- actor and authenticated principal class;
- target resource and operation;
- authoritative producer identities;
- trust state and reason codes;
- policy version or policy-set identifier;
- decision (`allow`, `allow_and_log`, `warn`, `step_up`, `restrict`, `quarantine`, `revoke`, `block`, `isolate`, or `escalate`);
- decision time and expiry/freshness semantics;
- evidence references rather than embedded secrets;
- executor identity when a technical action occurs;
- audit correlation identifier.

High-impact decisions must be replay-resistant and scoped to the intended actor, resource, operation, and validity window.

## Runtime execution authorization

Wardveil Foundation 0.9 formalizes a cross-service execution boundary between Wardveil Policy and Wardveil Protect. A policy decision is evidence for what Wardveil decided; it is not automatically a command that any service may execute.

For high-impact cross-service actions, Wardveil issues or validates a short-lived execution authorization bound to the exact policy-record digest, policy record ID, correlation ID, action, target scope, executor ID, idempotency key, replay nonce, issue time, and expiry. The authorization cannot outlive the policy decision that produced it.

The canonical source reference is `reference/wardveil_runtime_authorization.py`; the machine-readable contract is `contracts/wardveil.runtime-authorization.json`; and the operational boundary is documented in `RUNTIME-AUTHORIZATION.md`.

The dependency-free reference uses HMAC-SHA256 only for conformance testing and labels it `HMAC-SHA256-reference-only`. Production cryptography, key storage, rotation, revocation, authenticated transport, and durable replay/idempotency storage remain deployment-specific acceptance requirements.

A valid authorization does not transfer ownership of the target resource and does not override the executor's own action/resource authority. GoreeCloud Mesh may transport authorized requests, but transport authenticity and execution authority remain distinct checks.

## Detection and scanning model

Wardveil Detect and Wardveil Scan must distinguish observation from proof. Findings should carry confidence, severity, source, scope, freshness, and evidence references. Anomaly alone must not automatically be promoted to confirmed malicious activity.

Unknown or unsupported inspection results are represented explicitly. They are not silently interpreted as clean.

## Quarantine model

Quarantine is a controlled security state, not deletion. A quarantined object must retain enough metadata for investigation and recovery while preventing ordinary use. Release, removal, or restoration requires an explicit authorized action and an audit record.

## Response model

Wardveil Response coordinates incidents across first-party systems while preserving local authority. It may request or orchestrate actions such as session revocation, credential disablement, application isolation, malicious-object removal, policy tightening, administrator notification, and Everkeep-assisted recovery. Each action must identify the authoritative executor and produce audit evidence.

## Platform relationships

- **Privacy Shield** owns privacy-control contracts, tracking resistance, data minimization expectations, and privacy-specific runtime behavior. Wardveil may consume sanitized privacy status but does not inherit Privacy Shield authority.
- **Everkeep** owns resilience, backup, recovery, preservation, portability, succession, and digital-legacy capabilities. Wardveil can detect and contain compromise; Everkeep can restore protected state; Wardveil can verify the restored environment.
- **GoreeCloud Mesh** is the coordination and governance plane connecting first-party applications and services. Wardveil may use Mesh for authenticated signal transport, decision distribution, runtime-authorization delivery, and cross-service coordination while retaining Wardveil security semantics.
- **Glaze UI** defines the visual and interaction system used by Wardveil Security Center and embedded Wardveil surfaces.

## Application integration contract

GoreeCloud applications should not independently recreate the full Wardveil stack. They should:

1. produce scoped authoritative security signals;
2. request trust or policy decisions when required;
3. require a valid bound runtime authorization before executing supported high-impact cross-service Wardveil actions;
4. honor Wardveil enforcement decisions only through an executor whose own authority covers the requested action and resource;
5. submit supported content to Wardveil Scan rather than inventing incompatible scan semantics;
6. respect quarantine state and release authorization;
7. emit security-relevant events to Wardveil Audit;
8. expose only evidence-backed Wardveil status through Glaze UI;
9. fail closed when a required Wardveil contract cannot be validated.

Branding alone never counts as integration.
