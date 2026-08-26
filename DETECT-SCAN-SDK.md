# Wardveil Detect + Scan Reference SDK

Wardveil Detect and Wardveil Scan are evidence-generation layers for the Wardveil security plane. The dependency-free implementation in `reference/wardveil_detect_scan.py` provides deterministic reference behavior for threat findings, anomaly handling, scan outcomes, confidence, severity, correlation, and canonical runtime-record serialization.

It is not a production malware engine, URL reputation service, sandbox, antivirus product, behavioral analytics backend, or threat-intelligence feed. Authoritative GoreeCloud integrations must supply current evidence from systems that actually perform those functions.

## Detection boundary

Wardveil Detect can classify evidence as `informational`, `suspicious`, `likely_malicious`, `confirmed_malicious`, or `unknown`.

An anomaly alone never becomes `confirmed_malicious`. Behavioral or authentication anomalies require corroboration. A confirmed malicious disposition requires an explicit confirmed indicator from an authoritative producer. Unverified evidence fails closed to `unknown`.

Severity and confidence are carried separately. High confidence does not by itself change an anomaly into confirmed malicious activity.

## Scan boundary

Wardveil Scan returns exactly one of `clean`, `suspicious`, `malicious`, `unknown`, or `unsupported`.

`clean` is permitted only when the scanner supports the represented resource, the scan actually completed, and no material suspicious or malicious result was found. Unsupported resources remain `unsupported`; incomplete or unavailable scans remain `unknown`. Neither state may be normalized to clean.

## Correlation

Detection correlation preserves the strongest disposition already supported by the supplied findings and merges their evidence references. Correlation does not invent a stronger disposition than any authoritative input justifies. This keeps cross-application correlation useful without turning multiple weak anomalies into fabricated certainty.

## Runtime records

`DetectionFinding.as_runtime_record()` emits a canonical `detection_finding` record with disposition, severity, confidence, validity, evidence, producer, and scope. `ScanFinding.as_runtime_record()` emits a canonical `scan_finding` record with the scan result, validity, evidence, producer, and scope.

## Acceptance boundary

This reference SDK demonstrates contract behavior and reusable implementation semantics. It does not establish production deployment, scanner efficacy, threat-intelligence coverage, product-specific runtime acceptance, or Stable qualification. Those claims require product-specific integration evidence and validation.
