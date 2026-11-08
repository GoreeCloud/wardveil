# Wardveil — Cloudflare Security Audit Skill: controlled evaluation

| Field | Value |
| --- | --- |
| Owner | GoreeCloud / Wardveil |
| Date | November 7, 2026 |
| Status | **Source-integrity gate implemented and locally tested; agent execution and integration NOT approved or performed** |
| Candidate upstream | [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill) |
| Reviewed source revision | [`c1c8a8c1471069fb0e188eeaff69b8e8db6564a8`](https://github.com/cloudflare/security-audit-skill/commit/c1c8a8c1471069fb0e188eeaff69b8e8db6564a8) (`main` as checked November 7, 2026) |
| License / author | MIT; Cloudflare, Inc. Copyright notice belongs to upstream |
| Scope | Local, read-only repository integrity checking and future authorized source-code audit pilot only |

## Why this is being evaluated

The upstream project is a **coding-agent methodology**, not an antivirus engine or Wardveil runtime service. Its six-phase workflow covers reconnaissance, coverage-led hunting, candidate challenge, structured finding records, independent verification, and reporting. Wardveil Scan could eventually ingest validated source-code findings, while Wardveil Trust could retain minimal provenance and evidence. Neither integration is implemented by this change.

**GoreeShield** owns evidence privacy/retention/consent; **Wardveil** owns vulnerability assessment; **GoreeCloud Identity** controls authorization; **GoreeCloud Mesh** exchanges only approved results; and **GoreeCloud UI** governs any future display. No external model may receive private GoreeCloud source, local secrets, production logs, or private finding payloads without explicit applicable authorization.

## Implemented read-only source-integrity gate

`tools/security-audit-pilot/preflight.cjs` verifies **all 22 upstream tracked files** against the exact Git object IDs and byte lengths from the pinned commit's tree. It rejects missing, modified, additional, symbolic-link, non-regular, or oversized tracked files; validates manifest paths; and accepts only a real directory. Git metadata (`.git`) is intentionally not examined. The checker does not invoke Git, npm, the upstream validators, a coding agent, a shell, or any code from the candidate repository. It does not install dependencies, execute target-controlled processes, access the network, write files, or modify the source.

The checker requires **Linux** with the expected `O_NOFOLLOW` and `O_NONBLOCK` file-open flags. This is an integrity check of a locally supplied snapshot, **not** proof of upstream authorship, sandboxing, freedom from malicious instructions, absence of TOCTOU races in a concurrently mutable directory, or security of a future audit. SHA-1 values are Git's content-addressed blob IDs, not independent SHA-256 attestations. Protect the verified source directory against modification between the check and any separate evaluation.

Read-only usage, after a human reviews and obtains the pinned candidate source through an approved process:

```sh
# Supply an absolute path to a disposable, isolated checkout at the pinned commit.
node tools/security-audit-pilot/preflight.cjs /absolute/path/to/security-audit-skill

# Unit tests for this checker only; they do not execute upstream code.
node --test tools/security-audit-pilot/preflight.test.cjs
```

`PASS` means **only** that the supplied file set matches the pinned manifest. `BLOCKED` exits nonzero and must prevent progress; never bypass the gate by changing the pin or manifest merely to accommodate unexpected content. A revised upstream commit requires a fresh code/license review and a new complete manifest in a separate PR.

## Threats and currently open upstream issues

- [Upstream issue #128](https://github.com/cloudflare/security-audit-skill/issues/128): an external reporter describes destructive damage to their Windows profile after an agent tried to prepare a sandbox. This is a user report, not an independently reproduced incident; it justifies a strict rule: **never wipe, reset, truncate, move, or clean real HOME, cache, credentials, toolchains, SSH directories, or any host state to create a sandbox**.
- [Upstream issue #117](https://github.com/cloudflare/security-audit-skill/issues/117): Windows validator CLIs reportedly reject input because POSIX no-follow/nonblocking flags are not available. Windows execution is unsupported in this pilot; do not weaken source integrity checks with an unreviewed plain-open fallback.
- The skill's report validators check schema and record consistency, **not factual vulnerability correctness**. Independent rechecks and small safe proof fixtures remain mandatory.

## Required gates before any agent-assisted pilot

1. **Authorized source and target:** Document exact upstream commit, audited target's repo/commit, authorized ownership, scope, excluded paths, and third-party license notices. Start with a small *public* GoreeCloud repository with no live credentials or personal data.
2. **Provenance and static review:** Run the integrity preflight above; review every upstream Markdown prompt and both `.cjs` validators and tests for instruction hijacking, arbitrary execution, credential access, network requests, destructive behavior, and unsafe path assumptions. Do not auto-install the skill globally.
3. **Real isolation:** Use an externally provisioned, disposable Linux VM or OS-enforced sandbox with **no external network for target-controlled processes**, no host credential mounts, no host HOME, read-only source and toolchain, scratch-only writes, explicit safe environment variables, CPU/memory/process/file/disk/time limits, and independent enforcement evidence. A virtual environment or prompt instruction is not an OS sandbox. If the controls are unavailable or cannot be proven, **no target execution**; use guidance-only source review and label blocked claims `needs_validation`.
4. **Non-destructive scope:** No production endpoints, real accounts, user data, host cleanup, privilege changes, remote devices, shell installers, dependency downloads, automatic remediation, or network probing. Only synthetic local fixtures may be used under separate authorization and sandbox gates.
5. **Observe-only reporting:** Capture redacted, bounded verdicts (`confirmed`, `needs_validation`, `rejected`), coverage ledger, exact source/target commit, source trace, independent verification, known gaps, elapsed time, agent/model invocation counts, token/cost estimates where available, and safety incidents. A JSON schema-valid report is not a certified vulnerability.
6. **Acceptance review:** Compare at least one repeat run to a baseline manual/static review. Track false positives and missed coverage, preserve a documented rollback and temporary storage deletion plan, and receive explicit gate review before any repository automation or API integration.

## Integration and release boundaries

The current change does **not** vendor Cloudflare's source, change Wardveil's security-event or scan contract, add background agents, install or execute the skill, fetch third-party dependencies, expose APIs, or publish reports. Upstream's MIT terms apply if its code is subsequently copied or redistributed; preserve author attribution and notices. Wardveil's own repository-license decision remains pending in [PR #23](https://github.com/GoreeCloud/wardveil/pull/23) and must be settled independently.

**Next priority:** Run a read-only pilot only after the sandbox and explicit target are independently validated; then design a versioned, minimally retained advisory finding-ingestion contract and test it before exposing any UI or automation. Until then, this is an evaluated candidate with a locally tested integrity gate, not an operational scanner.
