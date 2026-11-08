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

`tools/security-audit-pilot/preflight.cjs` verifies **all 22 upstream tracked files** against the exact Git object IDs and byte lengths from the pinned commit's tree. It rejects missing, modified, additional, symbolic-link, non-regular, or oversized tracked files; validates manifest paths and symlinked ancestors; and uses pinned Linux directory descriptors to reduce rename/replacement races during traversal. It accepts only a real directory. Git metadata (`.git`) is intentionally not examined. The checker does not invoke Git, npm, the upstream validators, a coding agent, a shell, or any code from the candidate repository. It does not install dependencies, execute target-controlled processes, access the network, write files, or modify the source.

The checker requires **Linux**, `/proc/self/fd`, and the expected `O_NOFOLLOW`, `O_NONBLOCK`, and `O_DIRECTORY` file-open flags. This is an integrity check of a locally supplied snapshot, **not** proof of upstream authorship, sandboxing, freedom from malicious instructions, absence of TOCTOU races in a concurrently mutable directory, or security of a future audit. SHA-1 values are Git's content-addressed blob IDs, not independent SHA-256 attestations. Protect the verified source directory against modification between the check and any separate evaluation. Directory descriptors reduce traversal races, but do not make a concurrently writable tree immutable.

Read-only usage, after a human reviews and obtains the pinned candidate source through an approved process:

```sh
# Supply an absolute path to a disposable, isolated checkout at the pinned commit.
node tools/security-audit-pilot/preflight.cjs /absolute/path/to/security-audit-skill

# Unit tests for this checker only; they do not execute upstream code.
node --test tools/security-audit-pilot/preflight.test.cjs
```

`PASS` means **only** that the supplied file set matches the pinned manifest. `BLOCKED` exits nonzero and must prevent progress; never bypass the gate by changing the pin or manifest merely to accommodate unexpected content. A revised upstream commit requires a fresh code/license review and a new complete manifest in a separate PR.

## CI verification of the real pinned source

The separate [`verify-pinned-audit-skill.yml`](../.github/workflows/verify-pinned-audit-skill.yml) workflow runs on changes to this pilot and can also be dispatched after it exists on the default branch. It uses read-only GitHub Actions credentials to check out a **public, immutable Cloudflare commit** into a temporary GitHub-hosted runner directory and runs only our first-party `preflight.cjs` against that source. It **does not run Cloudflare's scripts, download model dependencies, invoke a security agent, mount an owner device, or alter a deployment**. The job's successful exact-commit result establishes upstream file-byte matching in that CI run only; it does not prove the skill is safe to execute.

This narrowly scoped GitHub checkout requires normal CI network access to retrieve the public Git content. That is different from the separately prohibited external network for **target-controlled** code during a future security audit. Neither a passing CI integrity job nor the local user/network namespace smoke test is proof that an executable audit sandbox meets the privacy, resource, and isolation requirements.

## Offline created-container policy gate (implemented; no runtime authorization)

[check-container-policy.cjs](../tools/security-audit-pilot/check-container-policy.cjs) evaluates an **offline JSON snapshot** of Docker's inspection metadata for exactly one **created, not started** container. It never calls Docker, creates/starts containers, reads host secrets, downloads images, opens sockets, or executes the candidate skill or target.

The static policy currently requires:

- Network mode `none`, no published ports, no host PID/IPC/cgroup namespaces, no host links, and no device access.
- Read-only container root, unprivileged numeric UID:GID, dropped capabilities, `no-new-privileges`, and a non-unconfined AppArmor profile.
- PID limit 1–32, memory 64–512 MiB, no additional swap, CPU at most 1, and OOM killing enabled.
- Only a digest-pinned image reference approved externally; an exact read-only source bind under `/srv/wardveil-audit-pilot/source/`; no other host mounts, image volumes, or inherited container volumes.
- Small in-memory-only `/scratch` (64 MiB) and `/tmp` (32 MiB) with `nosuid,nodev,noexec`; exact safe `HOME`, `TMPDIR`, `PATH`, and `LANG` environment values, with no other environment variables.
- No container healthcheck execution, automatic restarts, sysctl overrides, or persistent host-side container log driver.

The checker refuses a running/previously started container. It reads at most 128 KiB of input through a Linux no-follow/nonblocking regular-file descriptor and does not echo raw inspection content or environment values. It returns **`STATIC POLICY MATCH ONLY`**, deliberately not "sandbox verified". The command requires an explicit image digest and a separately vetted host source path. Example syntax (illustrative only; **do not create/start a container without separate authorization and reviewed isolation design**):

```sh
node tools/security-audit-pilot/check-container-policy.cjs \
  /absolute/private/path/to/inspect.json \
  --image '<reviewed-image>@sha256:<exact-64-hex-digest>' \
  --source /srv/wardveil-audit-pilot/source/<reviewed-target>
```

The checker **does not** independently establish that the inspection file comes from the actual Docker engine or that the image bytes match its claimed digest. It also cannot prove external network blocking or filesystem isolation under real execution. An operator must independently verify a rootless daemon or effective user-namespace remapping, active kernel seccomp/LSM enforcement, protected snapshot ownership, mounted source permissions, network isolation, runtime resource controls, and a trusted execution path on a disposable nonproduction host before any audit execution. A Docker `HostConfig.UsernsMode` value of an empty string means "use daemon policy"—**not** automatically "private"; Docker documents `host` as the only explicit `--userns` override. See [Docker run user namespaces](https://docs.docker.com/reference/cli/docker/container/run/#disable-namespace-remapping-for-a-container---userns) and [Docker userns-remap](https://docs.docker.com/engine/security/userns-remap/).

**Test evidence:** 42 locally passing synthetic policy tests, including rejection of host mounts, secrets in environment, root users, host namespaces, extra volumes, privileged execution, no limits, and malformed or non-regular input. The tests do not provision, inspect, start, or validate a real Docker container. Combined with 15 source-integrity tests, 57 local tests pass at the development checkpoint. GitHub CI on the updated PR must be read back separately before reporting a hosted pass.

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

## Proposed first pilot target and source-only baseline (November 7, 2026)

**Candidate:** the authorized public repository [`GoreeCloud/wardveil`](https://github.com/GoreeCloud/wardveil) at `main` commit `41ff4766719e87a3f5399359d0e721cce5df9493`. This is a **candidate selection and read-only baseline**, not authorization to launch target code or an AI-agent audit.

Source-only observations from that revision, for later audit quality comparison:

| Surface | Verified source fact | Audit comparison question |
| --- | --- | --- |
| `cmd/wardveil/main.go` | The development service requires a literal loopback IP listener and bounds HTTP timeouts. | Does an agent incorrectly report an internet-exposed listener without deployment evidence? |
| `internal/httpapi/server.go` | The two API paths use distinct bearer-token hashes; event input has a 4096-byte body limit, JSON field controls and a bounded list query. | Does it trace auth and parsing before asserting a boundary bypass? |
| `internal/core/event.go` | Typed event identifiers, severity, schema and timestamps are validated. | Are claimed input failures reachable after validation? |
| `internal/store/store.go` | A local JSONL journal checks private permissions and record bounds. Its directory/file open sequence is path-based in the reviewed default branch. | Does it recognize filesystem substitution and platform ownership assumptions, including the unmerged proposed corrective [PR #19](https://github.com/GoreeCloud/wardveil/pull/19)? |
| `internal/scan/contracts.go` | The scanner contract carries metadata and advisory verdicts only; it does not read or execute file bytes. | Does it avoid falsely claiming deployed malware scanning or quarantine enforcement? |

**Current assessment:** This limited source-only baseline produced no independently reproduced, confirmed vulnerability. Potential journal filesystem-substitution risks and existing pending patches require controlled validation; do not label any proposed issue as confirmed without an independent source trace and safe fixture result. As additional code is merged, re-pin the target revision rather than silently mixing old and new source evidence.

A targeted static pass also inspected the 22 files in the pinned upstream skill. The two validator CLIs contain read-only file handling and bounded JSON validation; their test suites spawn Node child processes and remove their own generated temporary directories. The published Markdown instructions request OS-enforced sandboxing but **cannot enforce it by themselves**. This does not certify the skill as safe or substitute for complete independent review of execution behavior. No upstream code was executed in this assessment.

## Integration and release boundaries

The current change does **not** vendor Cloudflare's source, change Wardveil's security-event or scan contract, add background agents, install or execute the skill, fetch third-party dependencies, expose APIs, or publish reports. Upstream's MIT terms apply if its code is subsequently copied or redistributed; preserve author attribution and notices. Wardveil's own repository-license decision remains pending in [PR #23](https://github.com/GoreeCloud/wardveil/pull/23) and must be settled independently.

**Next priority:** Run a read-only pilot only after the sandbox and explicit target are independently validated; then design a versioned, minimally retained advisory finding-ingestion contract and test it before exposing any UI or automation. Until then, this is an evaluated candidate with a locally tested integrity gate, not an operational scanner.
