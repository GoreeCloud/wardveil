# Wardveil — PHP2Shell Offline Advisory Assessment

| Field | Value |
| --- | --- |
| Product | Wardveil cybersecurity |
| State | Development-only candidate; neither deployed nor accepted |
| Updated | November 7, 2026 |
| Scope | CVE-2026-109618 and CVE-2026-109619; read-only version classification |
| Source | [PHP upstream security releases](https://www.php.net/archive/2026.php), October 21, 2026 |
| Issue | [Wardveil issue #5](https://github.com/GoreeCloud/wardveil/issues/5) |

## Purpose

I require Wardveil to support urgent security triage without guessing about deployed assets or collecting unnecessary private information. This experimental assessment is an **offline aid**, not a vulnerability scanner, authenticated runtime inventory, package-repository lookup, incident investigation, or patch executor. It cannot prove a host is exposed, safe, compromised, or patched.

The official upstream security-release thresholds for these two CVEs are:

| PHP branch | First upstream fixed release |
| --- | --- |
| 8.2 | 8.2.35 |
| 8.3 | 8.3.36 |
| 8.4 | 8.4.27 |
| 8.5 | 8.5.12 |

Older unsupported versions and unrecognized future branches require independent review. A distribution, panel, appliance or hosting vendor may backport patches without changing the upstream version number. Do **not** declare exposure or remediation solely from this tool's version comparison.

## Local use (development)

The Go command reads a single JSON array from **stdin**, no more than 64 KiB and 128 records. It accepts exactly the string fields `version` and `role` per record. The role values are `web` (verified web-serving runtime), `cli` (verified CLI-only), and `unknown` (not verified). The tool rejects duplicate keys, extra fields, malformed JSON, empty lists and oversized inputs.

With the development branch checked out, use **fictional test data**:

```sh
printf '%s\n' '[{"version":"8.4.26","role":"web"},{"version":"8.4.27","role":"unknown"}]' \
  | go run ./cmd/php2shell-assess
```

Outputs are JSON: a fixed schema/scope marker, input record indexes, patch-threshold classifications, role states and recommended verification queues. They deliberately omit the source version strings, hostnames, process arguments and identifiers. Avoid entering any credentials, personal records or raw incident telemetry. Keep the input inventory private; stdout is still operational information to protect.

## Interpreting results

- `below_upstream_fix_threshold`: A supported branch is below the corresponding upstream security-release number. Confirm the **actual running web worker** and whether the exact vendor build has a verified backport. Treat web-serving cases as urgent until verified.
- `upstream_fixed_threshold_met`: The supplied number meets the listed upstream threshold, **not proof that the running process was updated, restarted or tested**.
- `legacy_or_vendor_specific`: Unsupported or vendor-maintained legacy branch. Require explicit supplier and runtime verification.
- `unrecognized_branch` or `invalid_version`: Evidence is insufficient. Do not convert an unknown result into safe/cleared.
- A role of `cli` means an independently verified CLI-only context, not proof that no other PHP service exists. `unknown` leaves web exposure unresolved.
- `urgent_verify_patch`, `verify_web_exposure`, `verify_vendor_patch`, `verify_inventory` and `verify_running_runtime` indicate **human/operator follow-up**, never authorized security actions.

## Limitations and release gates

Before any real product promotion, I require (1) authenticated per-deployment inventory including containers and vendor-embedded runtimes; (2) package provenance and verified vendor backport evidence; (3) running worker identity/restart proof; (4) investigation of suspicious logs/events where authorized; (5) remediation via separately approved change control; and (6) evidence that the specific source service is healthy afterward. No active host scanning, automatic patching, firewall changes, credential rotation, network calls, HTTP listeners or enforcement are implemented.

CVE-2026-115560, mentioned separately in some 2026 advisories, is **outside the scope** of these two thresholds. Do not conclude it is resolved from this classification.

This source-only development candidate remains separate from the Wardveil Scan ClamAV draft chain and GoreeShield privacy authority. GoreeCloud Mesh must not mistake an advisory result for permission to modify a service.
