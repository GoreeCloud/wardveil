# Wardveil Security Integration Guide

## Purpose

This guide defines how GoreeCloud applications and services should adopt Wardveil-facing presentation without transferring technical authority away from the systems that actually enforce security.

## Integration principles

1. **Preserve the underlying authority.** A Wardveil surface may summarize or present security state, but it must identify or preserve the technical source of that state when doing so matters to interpretation or action.
2. **Do not turn branding into evidence.** Wardveil branding alone is not proof that a control succeeded.
3. **Use evidence-scoped protection claims.** Display **Protected by Wardveil** only when the current displayed scope has authoritative evidence supporting that protection state.
4. **Keep security details useful but minimized.** Do not expose secrets, reusable credentials, private keys, tokens, recovery codes, sensitive topology, raw diagnostics, or unnecessary personal information merely to make a Wardveil view appear detailed.
5. **Use Glaze UI.** Wardveil-facing user interfaces follow Glaze UI semantics and accessibility expectations.
6. **Keep product identities intact.** Wardveil may appear within GoreeCloud Manager, Browser, Monitor, Network, Backup, Notify, Memos, or other applications without replacing the identity of those products.
7. **Keep Privacy Shield intact.** Browser-level Privacy Shield remains a named subsystem and may appear as one capability inside a broader Wardveil view.

## Appropriate uses

Appropriate Wardveil integrations include:

- security posture summaries;
- security settings and protection-state surfaces;
- actionable security warnings and recommendations;
- device-trust and enrollment state;
- vulnerability and security-update status;
- authentication or authorization security summaries;
- exposure and network-protection status;
- integrity and verification status;
- security-event history and audit presentation;
- compromise-response or security-recovery status;
- Privacy Shield status inside a broader Browser security view.

## Inappropriate uses

Do not use Wardveil to:

- rename a technical authority that already has a defined role;
- imply that a service is secure merely because Wardveil branding is present;
- conceal which system, policy, service, user, device, or control produced a security state;
- create a new security module solely from a reserved Wardveil name;
- duplicate authentication, firewall, VPN, secrets-management, vulnerability-management, backup, or recovery responsibilities without a separately approved architecture;
- collect additional telemetry or sensitive data merely to populate Wardveil presentation.

## Minimum presentation contract

A Wardveil-integrated surface should be able to answer, where applicable:

- **What is the security state?**
- **What scope does the state apply to?**
- **What authoritative system or control produced the state?**
- **When was the state last evaluated?**
- **Is the state verified, warning, degraded, unknown, or not applicable?**
- **What action can an authorized user take?**
- **What information is intentionally withheld for privacy or least privilege?**

Missing evidence is not passing evidence. Unknown, stale, unavailable, skipped, or unverified required security evidence must remain non-passing and must never be silently converted into a protected state.

## Interoperable status records

Applications that need a shared machine-readable representation should use the Wardveil status contract in `STATUS.md` and `contracts/wardveil.status.schema.json`.

The normalized presentation vocabulary is:

- **Protected** — current evidence supports the defined protection scope.
- **Attention** — action or review is recommended.
- **Degraded** — a protection or evidence path is operating below its intended state.
- **Unknown** — the required evidence is unavailable, stale, incomplete, or not yet verified.
- **Not applicable** — the control does not apply to the current scope.

These labels are presentation semantics only. They do not replace application-specific state machines or policy definitions.

A `Protected by Wardveil` claim is permitted only for the explicit scope of a record whose normalized state is protected, whose underlying source is authoritative, and whose required evidence is current. The claim must fail closed to false whenever those conditions are not satisfied.

## Security and privacy boundary

Wardveil integrations should prefer bounded, structured, privacy-conscious evidence. Broad presentation and observability paths should avoid reusable secrets, passwords, authentication material, request or response bodies, cookies, private keys, recovery codes, unnecessary network identifiers, and raw exception content unless a separately authorized security workflow genuinely requires them.

The authoritative system should retain detailed evidence when required. Wardveil-facing integrations should normally receive only the minimum state, source attribution, timestamps, sanitized summary, and authorized action information necessary for the user's decision.

## Canonical icon boundary

The status and integration contracts may be implemented before Wardveil's canonical icon is approved. Until the icon gate in `ICON.md` passes, applications may use text-based Wardveil integration but must not present a generic, inherited, or temporary icon as the official Wardveil visual identity.

## Original identity boundary

Wardveil Security is the original GoreeCloud security identity defined by this foundation. Current GoreeCloud project records do not identify a conflicting Wardveil Security identity.

Formal trademark or name-clearance work is optional future due diligence. It is not a current integration, release, or visual-showcase gate. If GoreeCloud later pursues trademark registration, broad commercialization, app-store distribution, package publication, or another expanded public use, a separate review may be performed without changing the current Wardveil technical integration contract.
