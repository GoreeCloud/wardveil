# Wardveil — Cloudflare Security Audit Skill: controlled evaluation

| Field | Value |
| --- | --- |
| Owner | GoreeCloud / Wardveil |
| Date | November 8, 2026 (follow-up engineering review; original pilot research November 7) |
| Status | **Four first-party verification gates implemented; independent disposable-host runtime smoke performed and BLOCKED by supplementary group membership; exact Node-probe/host-witness acceptance, upstream execution, integration and deployment NOT approved or performed** |
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

- Network mode `none`, no published ports, no host PID/IPC/cgroup/UTS namespaces, no additional network attachments, host DNS/hosts settings, or supplemental groups; no host links or device access.
- Read-only container root, unprivileged numeric UID:GID, dropped capabilities, the **single exact** `no-new-privileges:true` security option (no extra overrides), and a non-unconfined AppArmor profile.
- PID limit 1–32, memory 64–512 MiB, no additional swap, CPU at most 1, and OOM killing enabled.
- Both an approved repository manifest reference (`image@sha256:<digest>`) and the separately approved, resolved local image ID (`sha256:<digest>`), checked for exact matches rather than simply well-formed hashes; an exact read-only source bind under `/srv/wardveil-audit-pilot/source/`; no other host mounts, image volumes, or inherited container volumes. Both the declared `HostConfig.Mounts` entries and observed `Mounts` must agree on a private-propagation, read-only bind.
- Small in-memory-only `/scratch` (64 MiB) and `/tmp` (32 MiB) with `nosuid,nodev,noexec`; exact safe `HOME`, `TMPDIR`, `PATH`, and `LANG` environment values, with no other environment variables.
- No container healthcheck execution, automatic restarts **or auto-removal**, sysctl overrides, or persistent host-side container log driver.

The checker refuses a running/previously started container. It reads at most 128 KiB of input through Linux no-follow/nonblocking regular-file descriptors, opening each path ancestor relative to an already-pinned directory handle; symlinked ancestors, noncanonical paths, changed input, and oversized files fail closed. It does not echo raw inspection content or environment values. It returns **`STATIC POLICY MATCH ONLY`**, deliberately not "sandbox verified". The command requires the independently reviewed image manifest reference, local image ID, and host source path. Docker documents separate [manifest digests](https://docs.docker.com/reference/cli/docker/manifest/) and [image inspection IDs](https://docs.docker.com/reference/cli/docker/image/inspect/); the two are not interchangeable. Example syntax (illustrative only; **do not create/start a container without separate authorization and reviewed isolation design**):

```sh
node tools/security-audit-pilot/check-container-policy.cjs \
  /absolute/private/path/to/inspect.json \
  --image '<reviewed-image>@sha256:<reviewed-manifest-digest>' \
  --image-id 'sha256:<reviewed-local-image-id>' \
  --source /srv/wardveil-audit-pilot/source/<reviewed-target>
```

The checker **does not** independently establish that the inspection file comes from the actual Docker engine, or that a supplied image manifest digest actually resolves to the supplied local image ID. Both approvals require independent trusted provenance inspection. It only rejects disagreement between the supplied approved values and observed Docker inspect metadata. The latest checker additionally restricts the first-start process to a finite first-party host-witness probe. It also cannot prove external network blocking or filesystem isolation under real execution. An operator must independently verify a rootless daemon or effective user-namespace remapping, active kernel seccomp/LSM enforcement, protected snapshot ownership, mounted source permissions (including recursive submounts on older kernels), network isolation, runtime resource controls, and a trusted execution path on a disposable nonproduction host before any audit execution. A Docker `HostConfig.UsernsMode` value of an empty string means "use daemon policy"—**not** automatically "private"; Docker documents `host` as the only explicit `--userns` override. See [Docker run user namespaces](https://docs.docker.com/reference/cli/docker/container/run/#disable-namespace-remapping-for-a-container---userns) and [Docker userns-remap](https://docs.docker.com/engine/security/userns-remap/).

**Test evidence:** 75 first-party synthetic policy tests, including rejection of host mounts, secrets in environment, root users, host namespaces, extra volumes, privileged execution, no limits, and malformed or non-regular input. The tests do not provision, inspect, start, or validate a real Docker container. The current five-group test inventory is 15 source-integrity + 75 static container-policy + 62 kernel-probe + 73 host-witness + 5 no-execution regression = **230 automated tests**, all passing in GitHub CI on the last code revision before this documentation update. GitHub CI on the updated PR must be read back separately before reporting a hosted pass.

## Linux kernel self-probe (implemented; independent host verification still required)

For this pilot I require kernel-observed evidence in addition to the static Docker configuration check. The new [`runtime-probe.cjs`](../tools/security-audit-pilot/runtime-probe.cjs) reads **only the current process's** bounded Linux `/proc` and cgroup v2 files. It launches no subprocesses, changes no environment variable, executes no target or Cloudflare code, opens no network socket, and writes no files. It accepts **no path or configuration arguments**, preventing a caller from pointing it at a forged evidence directory through its CLI.

The probe checks: an explicitly non-root real/effective/saved/filesystem UID and GID, user/group ID maps that exclude host root, `NoNewPrivs: 1`, enforced kernel seccomp filtering, zero Linux capabilities (inheritable, permitted, effective, bounding, ambient), enforced AppArmor confinement, only the loopback network interface, and bounded cgroup v2 CPU/memory/PID/swap limits. It examines mountinfo for a read-only container root, a read-only `/source`, separate `/scratch` and `/tmp` tmpfs mounts with `nosuid,nodev,noexec`, and **no nested mounts** under any of those three paths. An exact allowlist of `HOME`, `TMPDIR`, `PATH` and `LANG` rejects inherited environment values. Missing/unreadable, malformed, unexpected or excessive input fails closed; raw environment and mount metadata are never printed.

The **only intended invocation** is by an independently verified operator *inside a freshly provisioned disposable, nonproduction, isolated test container*, running the trusted first-party probe before any third-party tooling. This is not a user-laptop/VPS procedure or an instruction to create or launch a container now:

```sh
node tools/security-audit-pilot/runtime-probe.cjs
```

A success message says **`KERNEL SELF-PROBE MATCH ONLY`**, not "runtime isolation certified". This probe is not a complete audit sandbox: it does **not** authenticate the container engine, its image or mount source, host network namespace identities, host-side ACLs, seccomp *filter contents*, AppArmor policy strength, egress controls on other pathways, `/etc/hosts` and other noncritical mount contents, or provenance and trustworthiness of its own execution. Filesystem limits and cgroup controls must be independently cross-checked from the **host side** in the designated disposable environment. It also requires cgroup v2 and an enforcing AppArmor LSM; unsupported Linux variants are **blocked**, not silently accepted. A static Docker configuration match plus a passing self-probe is **still insufficient by itself** to authorize agent execution.

The first-party synthetic test suite `runtime-probe.test.cjs` contains **62 passing unit tests**, including rejection of host-root mappings, writable source/submounts, disabled or missing seccomp/no-new-privileges, capabilities, non-loopback interfaces, unbounded cgroups, unenforced AppArmor, and extra environment variables. At the local development checkpoint, **230 first-party Node tests passed, 0 failed, 0 skipped** at GitHub CI commit `49012c92be9867a7fd3ccb0f015647168ef2f38b` (15 source integrity, 75 static policy, 62 kernel self-probe, 73 host witness, 5 no-execution regression). These are source and synthetic tests, not runtime host acceptance. A deliberate read-only invocation in the assistant's ordinary container **returned BLOCKED**, appropriately demonstrating that an arbitrary development environment cannot satisfy this restrictive profile. No actual target audit container was provisioned or started.

Sources used for the model: [Linux kernel proc documentation](https://www.kernel.org/doc/html/latest/filesystems/proc.html), [Docker seccomp](https://docs.docker.com/engine/security/seccomp/), [Docker user namespace isolation](https://docs.docker.com/engine/security/userns-remap/), and [Docker bind mounts and recursive read-only limitations](https://docs.docker.com/engine/storage/bind-mounts/).

## First-party, finite host-witness flow — new implementation (November 8, 2026)

**Code added:** `host-witness.cjs` and `host-witness.test.cjs`. The previously implemented static policy checker and kernel probe now agree on one exact initial command: Node executing `/opt/wardveil/runtime-probe.cjs --witness-window=90` in a separately reviewed, digest-pinned image. The static inspection refuses other entrypoints, commands, interactive TTY/stdin, startup wrappers, restarts, and additional exec processes. It still refuses to approve an already-started container.

The trusted kernel probe performs its usual read-only checks first. Only when those checks pass, the explicit `--witness-window=90` mode keeps **that first-party probe process**, not an agent, alive for at most 90 seconds. An expired window ends with a failed exit status. The probe never runs the candidate Cloudflare code, an installer, a scanner, shell scripts, a network client, or target-controlled code.

The read-only host witness accepts a **full Docker container ID**, the approved pinned image manifest reference, the separately reviewed local image ID, the independently reviewed SHA-256 of the exact first-party runtime-probe script, a separately verified source path, and an absolute inspection snapshot. It checks that the inspect data describes the same running first-start process. Without invoking Docker or starting anything, it reads `/proc/<pid>/stat`, namespace links, UID/GID maps, process status, mountinfo, net interfaces, and bounded cgroup-v2 limits. It compares the container's user, PID, mount, network, IPC, UTS and cgroup namespace inodes to host PID 1, checks that the process start time remains unchanged across capture, confirms the actual kernel-observed executable, exact NUL-delimited process arguments, and PID 1 identity within the child PID namespace, and requires the full 64-character container ID as an exact cgroup path component. It rereads cgroup membership, all seven host/process namespace identities, kernel UID/GID maps, security-bearing process-status fields, mount topology, AppArmor, CPU/memory/PID/swap limits, the executable path, exact process command line, and raw-byte SHA-256 of the first-party probe script after capture. Network interfaces are required to remain loopback-only, without comparing volatile traffic counters. It additionally reads the bounded first-party `/opt/wardveil/runtime-probe.cjs` file through the observed process's mount-root view and compares its **exact raw-byte SHA-256** to the independently reviewed hash. The byte-preserving bounded reader includes UTF-8 byte-order marks and non-UTF-8 bytes, avoiding false equivalence when decoded text differs from the actual file contents. A hash supplied on the command line is not itself evidence of source review or image provenance. It also rejects a process with an attached ptrace tracer or any supplementary groups, or without enforced seccomp, AppArmor, no-new-privileges and zero capabilities; unexpected host mounts and network interfaces; or missing cgroup limits.

Example **for a future explicitly authorized disposable nonproduction host only**:

```sh
node tools/security-audit-pilot/host-witness.cjs \
  /absolute/private/inspect.json \
  --id <verified-64-hex-container-id> \
  --image '<verified-image>@sha256:<reviewed-manifest-digest>' \
  --image-id 'sha256:<reviewed-local-image-id>' \
  --probe-sha256 'sha256:<reviewed-runtime-probe-file-sha256>' \
  --source /srv/wardveil-audit-pilot/source/<verified-public-fixture>
```

The corresponding synthetic host-witness tests include **73 unit cases**, including same-host-namespace rejection, process restart/PID reuse, bad cgroup identity, host-root mappings, unexpected mounts and failing resource limits. The bounded probe and the static checker reject alternate time windows.

**No container creation, starting, or agent execution is implemented or authorized in these scripts.** The host witness output is only `HOST KERNEL WITNESS MATCH ONLY`. A saved inspect file can be spoofed, kernel process command lines can be modified by sufficiently privileged processes, a host PID 1 can itself be namespaced, and stable two-point cgroup and executable/script readings cannot rule out every intermediate migration or execution change. Kernel namespace differences do not prove that a namespace has no dangerous escape, and observation does not attest actual image contents, host ACLs, network firewall, seccomp policy contents, AppArmor strength or immutable source bytes. The host owner must independently verify these facts and the trusted image/probe on a disposable system. If the Docker probe window expires or the host cannot observe it in time, the test is **BLOCKED**, not silently retried against production.

**Compatibility constraint discovered:** Docker's [official rootless limitations](https://docs.docker.com/engine/security/rootless/troubleshoot/) explicitly list AppArmor as unsupported for rootless mode, while this pilot requires enforced AppArmor. Consequently **Docker rootless alone cannot satisfy this exact pilot profile**. A dedicated, owner-approved nonproduction Linux host with **daemon userns-remap plus enforcing AppArmor**, cgroup v2 with functional CPU/memory/PID controllers, and an independently verified restrictive seccomp profile is a candidate architecture—not an installed or validated deployment. Alternatives such as a separate microVM require their own reviewed, adapted acceptance policy rather than silently bypassing AppArmor. Do not treat daemon userns-remap as equivalent to rootless Docker.

The kernel mount probe now rejects **all mountpoints outside** the four required roots and a narrow allowlist of known container-system mounts. It refuses unapproved mounts even when read-only, nested source/scratch mounts, writable sensitive system mounts, and unknown escaped paths. This may conservatively reject standard Docker-provided system mounts; real-host compatibility and safety must be verified, and the allowlist may only be changed after corresponding threat-model and negative-test review. Docker documents [recursive read-only submount limitations](https://docs.docker.com/engine/storage/bind-mounts/); a bare source `ro` flag is not sufficient proof.

## Read-only behavior regression guard (November 8, 2026)

The new first-party `no-execution-regression.test.cjs` test file checks the approved module imports for the four evidence programs and flags known subprocess, dynamic-import, network-client, destructive filesystem-writing and process-control APIs. It is an automated **regression tripwire only**, not a complete semantic analysis and not proof of absence of hidden execution behavior. One early CI run identified an overly broad pattern that confused regular-expression `.exec()` parsing with process execution; the test was corrected and the full Node suite passed at the commit documented above.

The host witness now requires complete container-ID cgroup path components rather than short prefixes, checks the actual NUL-delimited `/proc/<pid>/cmdline`, real executable path, host kernel PID, PID 1 inside the child PID namespace and stable cgroup membership at both ends of its observation window. Every match remains observational evidence only; privileged processes may falsify some signals, and this does not replace source provenance or disposable-host approval.

## Additional provenance checks (November 8, 2026)

Image provenance is now checked at two levels: an independently reviewed registry manifest/reference digest and the separately reviewed locally resolved image ID. The configured image reference must match the former, and Docker's resolved `Image` field must match the latter; both must be supplied explicitly. Even these two fields do **not** certify the image build or the registry: review the trusted image-inspection response and supply-chain attestations separately.

The host witness adds a third byte-level check against the runtime probe: a SHA-256 of the first-party JavaScript file as observed at the process's `/proc/<pid>/root/opt/wardveil/runtime-probe.cjs` path. The file is only **read**; no code is executed. The expected probe SHA-256 must come from a separately reviewed and protected source/build artifact, not be copied from a suspicious target environment. The host verifier also fails closed on missing/malformed approval metadata rather than accepting an incomplete reference. Failure to open the file, an oversized file, or a digest mismatch **blocks** the witness.

A passing result cannot prove a process is uncompromised, that a namespace is escape-proof, or that the Linux host is trustworthy. All actual runtime/container execution remains separately blocked pending independent authorization and environmental enforcement evidence.

## Additional fail-closed hardening (November 8, 2026)

**Container overrides and evidence preservation:** The static policy now permits exactly one Docker security option, `no-new-privileges:true`; additional options (including duplicate entries) fail closed. It also requires `AutoRemove: false` so the verification-only container cannot silently disappear before independent witness evidence can be reviewed. This does not authorize long-term evidence retention; GoreeShield privacy and a separately authorized deletion plan still govern temporary artifacts.

**Filesystem mutation and mount propagation:** The kernel probe's bounded raw-byte reader now compares inode, size and metadata before/after reading ordinary files. Procfs virtual files reporting zero length remain separately bounded but are not falsely treated as immutable on-disk files. Unit tests inject regular-file growth and same-length replacement during a read. The mount inspector rejects shared/master/propagation-from markers anywhere in the observed mount table, including source, temporary filesystems and system mounts. These are point-in-time observations, not proof against every concurrent attack.

**Evidence:** At the most recent code checkpoint, the four-gate suite and read-only regression tripwire contained **230 passing Node tests** across the five groups listed above, plus separately passing pinned-upstream integrity and editorial checks. The Go race-test workflow must be checked independently for the exact final PR revision.

## Host-witness process-stability checks (November 8, 2026)

The independent host witness now rechecks the kernel-observed executable symlink, exact NUL-delimited `cmdline`, and bounded first-party probe-file SHA-256 at the **end** of the capture, in addition to the existing PID start-time and cgroup rechecks. This guards against a process retaining its PID and creation time while replacing its executable or probe source during observation. Six new negative tests exercise changed or missing end-of-capture fields.

This is an observation-only defense against simple substitution races. It does **not** prove those properties were immutable at every instant, authenticate the Docker engine or image supplier, or authorize executing an untrusted agent. The target process could still change between independent samples, and the entire procedure still requires a separately verified disposable host and image provenance.

## Process-tracing, group and path-identity hardening (November 8, 2026)

The kernel self-probe and independent host witness both now require explicit `TracerPid: 0` and an empty supplementary `Groups:` field from the kernel's process status. Missing values fail closed, as do attached tracers and unexpected supplementary groups. This goes beyond static `GroupAdd` configuration and checks actual process state. A valid container running under a debugging tracer or with secondary group memberships will be conservatively rejected; no weaker fallback is enabled.

The host witness's first-party probe-file hash reader anchors the observed process's `/proc/<pid>/root` directory handle and opens `opt` and `wardveil` through descendant directory handles using `O_NOFOLLOW`; it also refuses a symlink at the final `runtime-probe.cjs` file. This prevents a symlink at an unreviewed parent path from redirecting the content being hashed. The initial process-root procfs magic link is necessarily followed to select the target process root; this alone does not authenticate the host, process, or underlying image. Positive and negative tests exercise normal source bytes and symlinks at all three path components.

**Evidence boundary:** These additions account for **10 new synthetic and fixture regression tests** beyond the previous 204. The GitHub-hosted Node job reported 214 passing tests on the implementing code revision; none of these tests provisioned or started a real audit container. No audit agent or third-party code was executed.

## Extended host evidence coherence and mount ambiguity rejection (November 8, 2026)

**Host capture coherence.** The independent host witness now records all seven host and process namespace inode references twice, requiring them to match across capture as well as differ between host and container. It also rereads the process UID/GID mappings, privilege- and identity-bearing `/proc/<pid>/status` fields, mountinfo, AppArmor, CPU/memory/swap/PID cgroup limits and network interface list. Missing, inconsistent or unsafe second readings fail closed. For status, only security-bearing fields are compared; volatile scheduling and memory counters are not. For networking, both readings must show loopback only; packet counters may differ. **Twelve negative tests** cover changes to network namespace, host namespace, UID map, AppArmor, process privileges, resource limits, mount topology and missing end-of-capture data.

**Mount identity.** The kernel mount parser now rejects duplicate, stacked and noncanonical mountpoint names *before* accepting any system mount allowlist entry. This addresses a possible ambiguous read of two mounts at the same allowed path. **Four additional negative tests** cover duplicate `/proc`, stacked `/etc/hosts`, noncanonical mount aliases and the corresponding host-witness case.

**Read-only behavior guard.** The separate source-pattern regression guard now flags additional file-descriptor write APIs, destructive file operations, computed filesystem-writing calls and write-enabled file-open flags. Its coverage is still heuristic: code review and sandbox isolation remain mandatory and untrusted code must never be executed simply because a source-pattern test passed.

**Evidence:** On implementing code head `49012c92be9867a7fd3ccb0f015647168ef2f38b`, all **230 first-party Node tests passed, zero failures/skips**, alongside Go formatting/vet/race, immutable upstream byte verification and editorial review in separate successful workflows. These are synthetic and read-only source tests. No real Docker/container-runtime acceptance, host LSM policy proof, image provenance verification, or third-party audit authorization is implied. A dual sample cannot establish every intermediate state or prevent a malicious privileged host from fabricating evidence.

## Independent runtime execution — blocked, not approved (November 8, 2026)

A dedicated [runtime isolation evidence report](./security-audit-runtime-isolation-evidence.md) now records **actual** kernel and hosted runner testing, rather than only synthetic Node fixture tests. The temporary local namespace test did create distinct namespace IDs but failed user-ID remapping, seccomp, no-new-privileges, effective capabilities, AppArmor proof and resource limits.

A GitHub-hosted Ubuntu runner's **default** Docker daemon passed eight read-only kernel/engine prerequisites but lacked daemon-wide user-namespace remapping: [host preflight run 42557758944](https://github.com/GoreeCloud/wardveil/actions/runs/42557758944). A **separate, disposable remapped Docker daemon** was then created on a hosted runner with isolated data/socket/exec roots. A source-only static Go probe was built with Go's standard library and no registry image pulls, target code or third-party audit agent execution. On [runtime run 42559488217](https://github.com/GoreeCloud/wardveil/actions/runs/42559488217), independent host-side checks confirmed distinct user/PID/mount/network/IPC/UTS/cgroup namespace identities, nonroot outside UID mapping, `NoNewPrivs: 1` and `Seccomp: 2`. The in-container probe nevertheless returned **`BLOCKED: supplementary group membership`** and exited nonzero.

**Mandatory disposition: FAIL/BLOCKED.** Do not weaken the no-supplementary-groups requirement, treat the hosted default daemon as suitable, or equate the partial Go smoke with the exact Wardveil Node kernel-probe and host-witness exchange. Additional image provenance, real network egress and mount enforcement, AppArmor/seccomp policy review, independently verified cleanup and GoreeShield privacy approval remain untested. No GoreeCloud owner VPS, laptop, production service or private data was modified; draft PR #24 and its existing acceptance task remain open.

## OCI zero-supplementary-group feasibility gate (November 9, 2026)

**Root cause confirmed in a live hosted process:** In [runtime diagnostic 42620805738](https://github.com/GoreeCloud/wardveil/actions/runs/42620805738), host-observed `Groups:` contained precisely the process's primary GID as a supplementary group, with no Docker `GroupAdd` configured. The in-container probe again returned **`BLOCKED: supplementary group membership`**. Moby's [`getUser` OCI construction](https://github.com/moby/moby/blob/master/daemon/oci_linux.go) explicitly initializes `AdditionalGids` with `usr.GID`. This is a source-supported explanation consistent with the real runner, **not a waiver of the strict empty-group requirement**. The Docker host/runtime acceptance workflows remain intentionally failing.

**Implemented separate offline checker:** [`check-oci-identity.cjs`](../tools/security-audit-pilot/check-oci-identity.cjs) reads a bounded, descriptor-safe OCI `config.json` without invoking OCI runtimes or writing to the bundle. It requires an explicitly empty `process.user.additionalGids` array, numeric non-root UID/GID 65534, all five OCI capability lists empty, no-new-privileges, a non-unconfined AppArmor request, a deny-by-default seccomp declaration, private namespace declarations, user/group mappings away from outside root, a read-only root, and the exact first-party Node probe startup and environment. Moby's primary-GID duplicate **fails** this checker. It produces **`OCI STATIC IDENTITY MATCH ONLY`**, never a runtime authorization or source provenance attestation.

**Verification:** [Wardveil foundation run 42621144506](https://github.com/GoreeCloud/wardveil/actions/runs/42621144506) passed **275 first-party Node tests, 0 failures and 0 skipped**, plus Go formatting/vet/race checks. New tests reject extra/missing OCI groups, root credentials, capabilities, host namespaces and user-map errors; they also check that the existing Docker smoke cannot silently weaken group refusal. A passed static OCI identity file does **not** prove kernel isolation, that its intended runtime will honor the file, AppArmor policy strength, or safe network/cgroup/mount enforcement. The existing source-integrity, Docker static policy, kernel, and host-witness gates remain intact.

**Next implementation boundary:** A separate reviewed OCI-runtime execution architecture would be required to enforce *actual* empty supplementary groups. Before any real execution, verify its runtime binary, OCI bundle provenance, LSM/seccomp filter policy, image trust, network/host namespace separation, resource bounds, controlled cleanup, and the same first-party kernel/host witnesses. Do not modify Docker-generated OCI state behind the daemon, run target code or Cloudflare agents, alter any production device, or merge/deploy this draft based on an offline OCI match. Detailed evidence is in the [independent runtime-isolation report](./security-audit-runtime-isolation-evidence.md).

## Offline OCI bundle-policy gate (November 9, 2026)

The existing [zero-supplementary-group OCI identity checker](../tools/security-audit-pilot/check-oci-identity.cjs) is now supplemented by a **separate, read-only [OCI bundle policy checker](../tools/security-audit-pilot/check-oci-bundle-policy.cjs)**. See the [proposed OCI bundle profile and remaining gates](./security-audit-oci-bundle-policy.md). The second checker first re-runs the identity gate, then requires a tightly bounded OCI mount table, explicit private recursive rootfs propagation, no lifecycle hooks or network-device injection, no unreviewed platform extensions, resource limits, deny-only device access, and a conservative seccomp default and syscall-rule structure. The allowed OCI configuration version is pinned to `1.1.0`. Unfiltered `clone`/`clone3`, namespace/mount syscalls, selected io_uring, userfaultfd and kernel-management operations are rejected by the static policy.

The checks run on a bounded, descriptor-safe `config.json` and **do not build, unpack, configure or execute an OCI bundle**. Their success output explicitly says *OCI STATIC BUNDLE POLICY MATCH ONLY*, not that an OCI runtime can start Node or preserve security policies. A future runtime will require independent binary, image, AppArmor, seccomp, mount, network, user/group, resource and GoreeShield privacy verification. The proposed exact syscall/device profile has **not** been demonstrated executable or functionally complete.

At the first implementing code checkpoint, [CI 42625343820](https://github.com/GoreeCloud/wardveil/actions/runs/42625343820) verified **356 first-party Node tests** on commit `090f4d5b7f742880c90a4ab6103f86aedb073c9e`, plus Go checks; later additional syscall-denial tests and this documentation revision must be verified on their own exact head. The default hosted Docker preflight and separate Docker runtime smoke still **FAIL CLOSED** on the previously verified namespace-remapping and supplementary-group problems. The new offline OCI gates do not change those findings, and no OCI-native runtime or third-party audit agent has been launched.

## OCI evidence parser and syscall allowlist hardening (November 9, 2026)

Following the offline [OCI bundle-policy review](./security-audit-oci-bundle-policy.md), the static validator now rejects **any syscall name outside a fixed 44-name proposed allowlist**, rather than relying on a finite list of known dangerous syscalls. New regression cases cover unreviewed network/socket entry points, file modifications and process creation/execution syscalls. The allowlist is intentionally **not an executable, independently audited Node seccomp profile**: ordinary OCI process startup may require `execve` and Node threads may require filtered `clone`. Neither permission is granted by this unexecuted static profile. A separately reviewed argument-filtered execution policy remains a prerequisite for any OCI-native runtime test.

The OCI identity and bundle CLIs also now parse the original bounded, descriptor-open `config.json` through a shared **duplicate-JSON-key rejection helper**. It detects repeated names even when the second key uses an equivalent JSON Unicode escape (for example `"a"` and `"\\u0061"`). It rejects excessive nesting, preserves ordinary pretty-printed JSON, and performs no second pathname-based read. This prevents ambiguous OCI review evidence; it does not prove how an external OCI runtime would parse the file. The legacy Docker-inspect JSON parsing path is unchanged.

These changes are implemented in the draft branch and covered by new Node regression tests, including CLI-level duplicate-key rejection and source import restrictions. **Their latest exact-head CI must be checked independently**; the last earlier verified baseline had 356 passing Node tests and did not include these latest cases. Real default-Docker and remapped-Docker runtime acceptance remain **blocked**, and no alternative OCI runtime or third-party audit skill was executed.

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
