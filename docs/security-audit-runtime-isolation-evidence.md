# Wardveil — Independent runtime-isolation verification evidence

| Field | Verified value |
| --- | --- |
| Date | November 8, 2026 (America/Chicago; GitHub log dated November 9 UTC) |
| Scope | Independently inspect disposable runtime isolation prerequisites for Wardveil security-audit pilot |
| Governing branch | `feat/security-audit-integrity-pilot-20261107`, draft [PR #24](https://github.com/GoreeCloud/wardveil/pull/24) |
| Disposition | **BLOCKED — no Wardveil audit sandbox is approved** |
| Testing code | First-party read-only host checks and a temporary isolated shell process; no upstream Cloudflare skill or target code executed |
| Connected devices | Online device names inventoried only; no VPS, personal laptop, production daemon or owner data accessed or modified |

## Independent test A — temporary local execution environment

Read-only kernel observations were taken directly from a temporary ChatGPT-managed Linux environment, not from an owner host.

- Linux kernel: `6.18.57 x86_64`.
- Container engines: `docker` and `podman` absent.
- Namespace syscall smoke: `unshare --user --map-root-user --pid --fork --net --mount --ipc --uts --cgroup -- sh` succeeded and started a temporary isolated process as PID 1. Seven namespace inode identifiers differed from the enclosing process. Network-interface listing exposed only `lo`. The process exited without a persistent workload.
- **Critical mapping failure:** inside `uid_map`, `0 0 1` — UID 0 is mapped to outside UID 0, not the required remapped nonroot host ID.
- **Critical process-policy failures:** `NoNewPrivs: 0`, `Seccomp: 0`, `Seccomp_filters: 0`, and nonzero effective Linux capabilities (`000001ffffffffff` in the namespace smoke).
- **Mandatory AppArmor enforcement:** not demonstrated; process label was `kernel`, not a verified `(enforce)` profile.
- **Cgroup limits insufficient:** `memory.max=4294967296` (4 GiB, above 512 MiB); `memory.swap.max=max` (unlimited, instead of zero); `cpu.max=400000 100000` (4 CPUs, above one); `pids.max=max` (unlimited).
- The inspected root filesystem was writable, not a verified `ro` audit container root.

**Verdict A: BLOCKED.** Namespace creation and loopback-only networking were independently observed, but user ID remapping, seccomp, no-new-privileges, capabilities, AppArmor, memory/CPU/PID/swap limits and a proper Docker container were not in place. This is an actual kernel smoke test, not complete Wardveil runtime verification.

## Independent test B — disposable GitHub-hosted Ubuntu runner

A new restrictive [PR-only read-only preflight workflow](../.github/workflows/wardveil-disposable-host-preflight.yml) inspected a fresh GitHub-hosted Ubuntu 24.04 runner. It performs no checkout, image pull, container build, container start, Docker daemon restart, or privileged host change. It queries only host files and the **local** Docker Unix socket, never an arbitrary remote Docker endpoint.

[Definitive verification run 42557758944](https://github.com/GoreeCloud/wardveil/actions/runs/42557758944) (first run [42557555520](https://github.com/GoreeCloud/wardveil/actions/runs/42557555520)):

| Host requirement | GitHub runner evidence |
| --- | --- |
| Linux x86_64 | PASS |
| Unified cgroup v2 | PASS |
| CPU, memory and PID cgroup controllers available | PASS |
| Host AppArmor module enabled | PASS |
| Local Docker socket and engine available | PASS |
| **Daemon-wide Docker user-namespace remapping** | **BLOCKED** |
| Docker AppArmor integration | PASS |
| Docker seccomp integration | PASS |
| Docker daemon using cgroup v2 | PASS |

The read-only job printed only these sanitized pass/block labels, ended nonzero with **one missing host prerequisite**, and did **not** create or start a Docker container. Therefore no actual runtime probe or host-witness exchange was performed. GitHub Actions represents this failure as a red workflow on purpose; it is an acceptance gate, not a code-test failure.

**Verdict B: BLOCKED.** The default hosted Docker daemon did not report mandatory daemon-wide `userns-remap`. No assertion about actual user namespace enforcement may be based on a successful static test or AppArmor/seccomp integration alone.

## Unresolved acceptance requirements

1. A demonstrably disposable, independently owned or approved Linux host with **effective Docker user-namespace remapping**, AppArmor enforcement, cgroup v2 CPU/memory/PID limits, and restrictive seccomp. Docker [userns-remap](https://docs.docker.com/engine/security/userns-remap/) is not equivalent to merely setting `UsernsMode` to an empty string; rootless Docker alone does not meet this profile's AppArmor requirement.
2. An independently reviewed, pinned, immutable image build; matching approved registry manifest and local image ID; source mount permissions and recursive read-only behavior; protected first-party probe SHA-256 and explicit ephemeral-host cleanup/recovery.
3. A **first-party-only container launch**, if and only if the host preflight is valid; compare a real `docker inspect` created-container snapshot with `check-container-policy.cjs` before the first start.
4. The in-container `runtime-probe.cjs --witness-window=90` and separate host-side `host-witness.cjs` must **both** pass on the identical process, with actual kernel namespace identities, UID/GID mappings, AppArmor, seccomp, mounts, network interfaces, and cgroups independently confirmed.
5. Independent verification of effective network egress denial, mount subtrees, process resource limits, image/probe provenance, failure recovery, privacy/retention boundaries and audit-agent execution prohibition. Only after all gates pass could an optional Cloudflare source audit be considered for separate authorization.

**Release disposition:** [Draft PR #24](https://github.com/GoreeCloud/wardveil/pull/24) remains unmerged; the existing Todoist runtime-acceptance task must remain open. Neither a working isolated namespace nor passing synthetic Node tests certifies the full runtime sandbox. Do not run third-party agents on a laptop, VPS, production host, or this unverified CI runner.
