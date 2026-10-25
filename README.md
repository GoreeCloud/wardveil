# Wardveil

**GoreeCloud's proposed unified security command center.**

> **Status:** Product vision and initial technical design. The repository currently contains planning documents only; it does not yet provide deployed threat detection, malware protection, WAF enforcement, or automated incident response.

Wardveil is intended to protect GoreeCloud infrastructure, applications, services, and their users through coordinated detection, intelligence, policy evaluation, security monitoring, and controlled response. It complements rather than replaces other GoreeCloud products.

## Product family

| Module | Responsibility |
| --- | --- |
| **Wardveil Security** | Unified security console, incidents, alerts, policies and posture |
| **Wardveil Scan** | Malware and vulnerability scans, verdicts and quarantine coordination |
| **Wardveil Shield** | Network/application protections, rate limits and authorized mitigations |
| **Wardveil Sentinel** | Continuous event, endpoint, and intrusion monitoring |
| **Wardveil Intel** | Threat feeds, reputations, enrichment and provenance |
| **Wardveil Response** | Auditable incident workflows and safeguarded response actions |
| **Wardveil Trust** | Security evidence, posture reporting and organizational transparency |

## Ecosystem boundaries

- **GoreeCloud Vault:** Owns password/secret/credential management, secure sharing, and Keycloak-related capabilities. Wardveil may request approved protective workflows through Vault-owned interfaces.
- **GoreeCloud Identity:** Owns identity, authentication, SSO, and Authentik-related capabilities. Wardveil may evaluate Identity signals and request Identity-owned sessions/protection actions.
- **Other GoreeCloud services:** Retain control of their content and runtime actions. Wardveil exchanges scoped events, verdicts, cases and policy-governed requests.

## Architecture direction

Design Wardveil as a **modular platform with replaceable provider adapters**, a normalized event and incident model, a policy engine, an isolated scan-worker design, a security command center, and verifiable audit trails.

Candidate technologies for evaluation include ClamAV, YARA, Trivy, CrowdSec, Cloudflare WAF, OWASP Core Rule Set, Wazuh, Suricata, VirusTotal, AbuseIPDB, URLhaus, AlienVault OTX and CISA KEV. Listing a provider is not a claim that the integration is installed, supported, licensed or deployed.

All interfaces must follow **GoreeCloud UI (GC UI)**, the project's governing design authority. Each declared native OS client or service requires an actual OS-targeted implementation and verification; a web wrapper is not a native substitute.

## Planning documents

- [Platform architecture](docs/architecture.md)
- [Security and trust model](docs/security-model.md)
- [Delivery roadmap](docs/roadmap.md)

## First development target

A minimal, verifiable file-scanning workflow: a source product holds an upload pending scan; Wardveil Scan analyzes the file in an isolated worker and returns a provenance-rich verdict; the source product applies its authorized hold/release policy; Wardveil Security records and displays the resulting finding. Start with **alert-only** response policies.

## Development and security posture

- Source content is private and untrusted by default. Do not upload private samples to public analysis providers without explicit authorization.
- Apply least privilege, validated inputs, response approvals, bounded policy scope, reversible actions, and independent action readback.
- Keep security events and evidence protected, redacted, tenant-scoped when applicable, and retained only as authorized.
- Use verified implementation and runtime results to claim functionality or release readiness; documents are not implementation evidence.

Wardveil is maintained in this repository. The current documents capture GoreeCloud founder intent and proposed design; implementation choices remain subject to applicable GoreeCloud governance and engineering verification.
