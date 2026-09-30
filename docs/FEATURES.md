# Wardveil Security — Feature Specification

Wardveil Security is GoreeCloud’s platform-wide security, protection, trust, detection, policy, verification, and response system. It is a functional technical subsystem embedded throughout GoreeCloud rather than a security badge, visual theme, or marketing label. Wardveil protects GoreeCloud applications, services, infrastructure, identities, devices, sessions, communications, and data while providing evidence for the security decisions and protections it performs.

This document defines the maintained feature scope for Wardveil Security Foundation 0.9 and the planned Wardveil 2.0 direction. Implementation and production acceptance remain evidence-bound; inclusion here defines implemented or intended capability as qualified by current evidence, not proof that every listed feature is operational or production-accepted in every GoreeCloud runtime.

## Core Security Features

- Platform-wide security architecture shared across GoreeCloud.
- Centralized security policy and enforcement.
- Identity and access protection.
- Device and session trust evaluation.
- Continuous security-risk evaluation.
- Threat detection and correlation.
- Security anomaly detection.
- Malware and malicious-content detection.
- Phishing and malicious-link protection.
- Suspicious-download detection.
- Security event correlation across applications and infrastructure.
- Automated and policy-driven protection actions.
- Security incident detection, containment, and response.
- Security evidence collection and audit history.
- Application and infrastructure security integration.
- User-facing and administrator-facing security management.
- Evidence-backed protection status.
- Shared security semantics through GoreeCloud Mesh.
- Consistent security experiences through Glaze UI.

## Identity and Access Protection

Wardveil integrates with GoreeCloud Identity while preserving responsibility boundaries. It supports user, application, service, machine, and device identity protection; authentication security; passkeys; MFA enforcement; authentication-strength evaluation; suspicious-login and login-anomaly detection; login throttling; brute-force and credential-stuffing defenses; credential-compromise detection and response; credential-change monitoring; session risk, provenance, age, and revocation; device trust, enrollment, integrity, and familiarity signals; privileged-access controls; least privilege; service identity protection; API credential protection and authorization; sensitive-operation reauthentication; risk-based authentication; and context-aware authorization.

The canonical access-evaluation chain is:

`Identity -> Authentication -> Device and Session Evidence -> Risk Evaluation -> Security Policy -> Authorization`

## Wardveil Trust

Wardveil Trust centrally evaluates evidence and determines trust state for identities, devices, sessions, applications, services, and requests.

### Trust signals

Supported signal classes include authentication strength and method; session age and provenance; device enrollment, integrity, familiarity, and previously unseen-device state; unusual authentication behavior; IP and network changes; geographic anomalies when legitimately available; requesting application or service; requested privilege; resource sensitivity; recent security events; credential changes; service-to-service identity; policy violations; suspicious file and URL findings; threat-detection results; prior compromise indicators; and application-integrity signals.

### Trust states

- Trusted
- Normal
- Elevated Risk
- Restricted
- Blocked

### Explainable trust decisions

Trust-state changes must be explainable through human-readable reasons, evidence references, contributing signals, and remediation guidance where appropriate. Wardveil must avoid arbitrary or unexplained security scores and inaccessible warning-only indicators.

## Wardveil Detect

Wardveil Detect is the shared threat-detection framework used across GoreeCloud instead of requiring each application to build an independent threat engine.

Detection scope includes malware, phishing, malicious URLs, suspicious domains, attachment and file findings, suspicious downloads, brute force, credential stuffing, account and service abuse, spam-related security signals, authentication and behavioral anomalies, suspicious access patterns, integrity checking, reputation information, compromise indicators, application, network, and infrastructure signals, and cross-application or cross-service correlation.

Authorized signal sources can include GoreeCloud Browser, Search, Mail, Drive, Vault, Messenger, AI, Identity, Gateway, Network, infrastructure, and internal services.

## Wardveil Protect

Wardveil Protect converts evidence and policy decisions into authorized protection actions.

Supported action classes include:

- Allow
- Allow + Log
- Warn
- Require Reauthentication
- Require MFA
- Require Passkey Authentication
- Restrict
- Quarantine
- Revoke Session
- Block Request
- Isolate Application
- Isolate Service
- Disable Credential
- Restrict Account Capability
- Notify User
- Notify Administrator
- Trigger Incident Workflow
- Require Manual Review
- Escalate Security Event

Protection actions must be policy-driven, evidence-based, scoped, auditable, and proportional. An anomaly alone is not automatic proof of malicious behavior.

## Wardveil Policy

Wardveil Policy provides centralized user, device, session, application, service, organization, infrastructure, authentication, authorization, privileged-access, API, file-handling, quarantine, threat-response, conditional-access, risk-based, and least-privilege policy evaluation.

The policy system supports inheritance, first-party enforcement, decision logging, and explainable policy outcomes. Decisions must carry explicit policy identity/version and sufficient context for later audit.

## Wardveil Scan

Wardveil Scan provides shared application-independent inspection for files, uploads, downloads, email and message attachments, malicious or suspicious content, file integrity, URLs, links, packages, and other supported payloads. Scan findings generate structured threat metadata and can integrate directly with Quarantine.

Unknown, unsupported, incomplete, or failed scan results are not equivalent to clean results.

## Application Security Integrations

### GoreeCloud Browser

Dangerous-site and malicious-navigation protection; phishing protection; malicious and suspicious-download handling; download inspection; permission-abuse detection; certificate and connection-security information; private-session protection; security-event reporting; website security indicators; contextual Wardveil warnings; browser-session security integration; Trust, Quarantine, and Security Center integration.

### GoreeCloud Mail

Phishing detection; malicious attachments and suspicious links; sender security indicators; email authentication-security information; spam and abuse signals; attachment quarantine; link inspection; account-compromise indicators; Wardveil threat reporting.

### GoreeCloud Drive

Upload scanning; malicious-file detection and quarantine; suspicious sharing; access monitoring; file-access events; unusual file activity; policy enforcement; download-security integration; compromise-response integration.

### GoreeCloud Vault

Stronger authentication for sensitive operations; reauthentication; passkey and MFA enforcement; secret-access auditing; sensitive-operation verification; session and device trust requirements; credential-compromise response; vault-access anomaly detection; secret-exposure protection; emergency session revocation.

### GoreeCloud AI

AI tool permissions; model and tool permission boundaries and isolation; prompt-to-tool security boundaries; secret protection; repository, file, and data-access authorization; identity-aware AI access; auditing of tool operations; least-privilege AI operations; prevention of permission bypass; security events for sensitive AI actions.

### GoreeCloud Messenger

Malicious-link and malicious-file detection; spam protection; account-abuse and suspicious-session detection; attachment and link inspection; sender/account security signals; compromise-response integration.

## Infrastructure Security

Wardveil extends below applications into servers, APIs, containers, databases, storage, internal services, deployment pipelines, and network boundaries. Infrastructure scope includes service-to-service authentication and authorization; secret management; API authorization and credential protection; rate limiting; dependency scanning; vulnerability management; integrity verification; container scanning; deployment verification; security-header and TLS policy enforcement; WAF integration; DDoS signals; internal segmentation; security-event collection; monitoring integration; and authorized automated containment.

External infrastructure protections may supply signals or enforcement capabilities while Wardveil remains GoreeCloud’s security abstraction, policy, coordination, evidence, and governance system.

## Wardveil Quarantine

Wardveil Quarantine provides centralized isolation and controlled remediation for malicious or suspicious files, downloads, attachments, message content, and other supported objects. Quarantine records include reason, evidence, source application, timestamps, and review state. Authorized controls can include safe recovery, removal, administrator review, false-positive handling, and policy-controlled restoration. All material quarantine actions are auditable.

## Wardveil Response

Wardveil Response supports security-incident creation, automated containment, account restriction, session revocation, credential disabling, application or service isolation, threat quarantine, user/admin notification and escalation, evidence collection, timeline generation, remediation, recovery coordination, post-incident verification, Everkeep recovery integration, and GoreeCloud Notify integration.

Cross-system response actions require explicit executor authority and audit evidence.

## Wardveil Audit

Wardveil Audit preserves security event history, authentication and authorization decisions, policy decisions, administrative actions, sensitive-operation auditing, session activity, device-trust changes, credential events, detections, protection actions, quarantine activity, incident-response activity, application and infrastructure events, and evidence associated with material decisions. It supports searchable investigation history without becoming an unrestricted secret or telemetry store.

## Wardveil Security Center

Wardveil Security Center is the centralized user and administrator experience for Wardveil.

### Protection Status

Current active protections, operational controls, protection health, supporting evidence, and degraded/unavailable warnings.

### Security Activity

Important security events, recent authentication activity, detections, protection actions, policy actions, and cross-application events.

### Sessions and Devices

Authenticated sessions, registered devices, device/session trust, details, security information, revocation and restriction controls, and suspicious-session indicators.

### Threats

Malware, phishing, malicious URLs, suspicious downloads, compromised credentials, suspicious account activity, application threats, and infrastructure threats.

### Quarantine

Isolated files, downloads, and attachments; explanations; evidence; review; recovery; and removal controls.

### Application Access

Applications and services with account access, permissions, sensitive permissions, service identities, revocation controls, and permission review.

### Security Policies

User, device, application, service, organization, authentication, conditional-access, and protection policies.

### Security Recommendations

Evidence-based improvements, stronger-authentication recommendations, weak-security configuration warnings, device and credential guidance, application-permission recommendations, and remediation guidance.

### Administrator Security Center

Organization-wide posture; incident investigation; policy management; threat correlation; cross-user events; device and session administration; application-access administration; remediation workflows; infrastructure visibility; audit and investigation tools.

## Wardveil Evidence

Wardveil maintains structured evidence behind security states and protection claims.

Evidence classes include authentication method, passkey/MFA state and authentication strength; session authentication, provenance, device trust, and risk state; browser dangerous-navigation, download-inspection, and phishing-protection health; upload/file scanning and quarantine health; TLS, active policy, infrastructure-control, and service-authentication state.

`Protected by Wardveil` must never be presented as a generic reassurance. The represented scope must be substantiated by identifiable controls, policies, trust decisions, detections, protection actions, operational state, events, or evidence.

## Privacy Shield Integration

Wardveil Security and Privacy Shield remain separate but interoperable platform systems.

Wardveil asks: “How do we prevent unauthorized access, compromise, abuse, and attack?”

Privacy Shield asks: “What information should be collected, retained, exposed, shared, or processed in the first place?”

Integration can include security-aware privacy enforcement, bounded shared permission context, protection of privacy-sensitive information, security controls for privacy systems, encryption integration, separation of security and data-minimization decisions, and explicit prevention of security functionality being used to justify unnecessary data collection.

## Everkeep Integration

Wardveil and Everkeep combine security and resilience through compromise and destructive-activity detection, ransomware-related signals, account-compromise containment, protected recovery, backup-integrity verification, recovery-security verification, and post-restoration trust verification.

Representative destructive-incident flow:

`Wardveil Detects -> Wardveil Contains -> Everkeep Recovers -> Wardveil Verifies`

## GoreeCloud Mesh Integration

GoreeCloud Mesh can provide authenticated coordination for security-event and threat-signal distribution, identity context, trust-state distribution, policy and protection coordination, application/service security contracts, capability discovery, cross-application correlation, event routing, incident coordination, Wardveil status propagation, and authorized evidence exchange.

Conceptually:

`GoreeCloud Mesh -> Wardveil Security -> Identity & Trust / Threat Detection / Policy -> Protection Engine -> GoreeCloud Applications and Services`

Mesh supplies coordination infrastructure while Wardveil owns Wardveil security semantics, trust decisions, policies, detections, protections, and responses.

## Glaze UI Security Integration

Glaze UI supplies standardized security indicators, severity terminology, security and permission dialogs, trust indicators, quarantine and remediation interfaces, accessible icons and text explanations, cross-device consistency, non-color-only state communication, progressive disclosure, and protection against excessive or meaningless warning banners.

Standard presentation hierarchy:

`Informational -> Protected -> Attention -> Elevated Risk -> Critical`

## First-Party Security Services

The canonical first-party services are Wardveil Trust, Protect, Detect, Scan, Policy, Quarantine, Audit, Response, and Security Center. These may remain internal services where appropriate; not every internal subsystem must become a separately branded user-facing product.

## Platform-Wide Wardveil Security Contract

Every supported first-party GoreeCloud application and service should be capable of integrating with Wardveil through a common security contract covering identity context, authentication context, authorization, trust evaluation, policy, threat submission/results, protection actions, quarantine, security events, evidence, audit records, incident response, user notifications, and administrative escalation.

Wardveil operates across GoreeCloud Identity, Browser, Search, Mail, Messenger, Drive, Vault, AI, Gateway, Network, Mesh, infrastructure, and other authorized GoreeCloud services.

The defining principle is **evidence-backed protection**. When GoreeCloud states that an application, session, file, account, device, or service is protected by Wardveil, there must be an identifiable security control, policy, trust decision, detection, protection action, event, or evidence record demonstrating what Wardveil actually did.

Wardveil Security is not merely a standalone security application. Wardveil is GoreeCloud’s shared security plane, with Wardveil Security Center serving as its primary visible management experience while the underlying security system operates throughout the GoreeCloud ecosystem.
