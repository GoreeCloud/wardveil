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

## Independent test C — actual first-party container, isolated remapped Docker daemon

After test B demonstrated that the **default** GitHub-hosted Docker daemon lacked remapping, a *separate* [PR-scoped hosted runtime workflow](../.github/workflows/wardveil-firstparty-runtime-smoke.yml) was implemented. It starts a newly configured Docker daemon under its **own** Unix-domain socket, daemon configuration, data root, execution root and PID file, with `--userns-remap=default`, no bridge or Docker-managed iptables. The existing hosted default daemon and all GoreeCloud owner devices are not modified.

The test builds a tiny **first-party Go static binary** with the runner's installed Go standard library, `GOPROXY=off`, `GOSUMDB=off`, `CGO_ENABLED=0`, and an empty scratch rootfs. No public or private container image is pulled, no unreviewed Cloudflare source is executed, and no target repository is mounted. It creates a disposable container with numeric unprivileged UID/GID, read-only root, dropped capabilities, `no-new-privileges`, Docker's seccomp/AppArmor integration, network mode `none`, private IPC/cgroups, a fixed test-only read-only source mount, bounded tmpfs and CPU/memory/PID/swap limits. The workflow cleans up only its named test container and process-scoped daemon; host trash/archive deletion commands are never used.

**Progress and explicit failure results:**

1. [First attempt 42558360195](https://github.com/GoreeCloud/wardveil/actions/runs/42558360195), [configuration-isolated 42558543232](https://github.com/GoreeCloud/wardveil/actions/runs/42558543232) and [traversal diagnostic 42558756929](https://github.com/GoreeCloud/wardveil/actions/runs/42558756929): isolated remapped daemon startup **BLOCKED** by insufficient path traversal for its remapped UID; the shared hosted runner's directory permissions were not relaxed. A unique disposable `/tmp` subtree with traversal-only directory permission resolved that test-lab issue.
2. [Image-execute attempt 42559061674](https://github.com/GoreeCloud/wardveil/actions/runs/42559061674): a separate remapped daemon started, image was imported and restricted container was created, but execution was **BLOCKED** by overly restrictive scratch-image binary/directory permissions. Adjusting only the first-party fixture's execute/traverse bits resolved that test-lab issue.
3. [Host-witness attempt 42559275226](https://github.com/GoreeCloud/wardveil/actions/runs/42559275226): the minimal first-party process **ran**. The independent host-side witness confirmed all seven container namespace inode identities differed from host PID 1, external UID 0 mapped to a **nonzero** host UID, `NoNewPrivs: 1`, and `Seccomp: 2`. The in-container probe returned `BLOCKED: kernel privilege flags`, exited nonzero; no acceptance was granted.
4. [Specific failure confirmation 42559488217](https://github.com/GoreeCloud/wardveil/actions/runs/42559488217): host-side namespace/remapping/no-new-privileges/seccomp checks again **matched**, while the in-container first-party probe returned **`BLOCKED: supplementary group membership`**. The kernel reported supplementary groups even though the container was configured with numeric UID:GID and no intentional `--group-add`. **This is the current concrete runtime blocking condition.**

The last run **failed acceptance**. Supplementary process group membership violates the existing strict Wardveil policy; it must not be reclassified as harmless based only on Docker's declared `GroupAdd` configuration. A future test may determine why this occurs and fix the image/runtime setup, but must not remove the test or silently accept unexpected group memberships. The simple Go smoke is also **not** the exact first-party Node probe plus full `host-witness.cjs` exchange, and it does not certify egress, source provenance, detailed mounts or recovery. Even a hypothetical successful Go smoke would still leave those mandatory gates open.

**Test confidentiality and cleanup:** Only generic safe `PASS`/`BLOCKED` labels and fixed failure categories were sent to public CI logs. No owner laptop, VPS, private source, production data, remote Docker daemon or Cloudflare agent was accessed. CI uses uniquely named short-lived, host-local data paths and exact-container cleanup, and hosted runner resources are ephemeral. The workflow's cleanup logic is present; independent post-run filesystem inspection is not claimed.

**Disposition C: BLOCKED on real in-container kernel process groups.** The default hosted daemon remains independently **BLOCKED** on user-namespace remapping. Keep draft PR #24 and the Todoist acceptance task open.

## Independent test D — why the Docker group cannot be cleared by GroupAdd configuration

A fresh [GitHub-hosted runtime diagnostic (run 42620805738)](https://github.com/GoreeCloud/wardveil/actions/runs/42620805738) explicitly compared the **host-observed** supplemental group array to the host-observed primary GID, without printing either numeric identity. Its sanitized result was:

> HOST GROUP EVIDENCE: primary GID also assigned as supplementary (strict zero-group policy still fails)

The in-container first-party Go probe separately returned **`BLOCKED: supplementary group membership`**. Docker inspection reported no intentional GroupAdd entries. Thus the exact runtime mechanism is now verified: the Docker-backed process carries the primary GID again within its supplementary group list, contrary to Wardveil's strict zero-supplementary-groups acceptance policy.

This agrees with Moby's [`getUser` OCI generation](https://github.com/moby/moby/blob/master/daemon/oci_linux.go), which initializes `usr.AdditionalGids = []uint32{usr.GID}` before adding user/GroupAdd memberships. The upstream source is a corroborating implementation explanation, not an independently authenticated attestation of the exact Docker build on every future host. In particular, `--group-add` being absent does **not** prove `AdditionalGids` is empty. **Do not reinterpret the primary GID appearing in the supplementary group array as a pass, and do not relax the zero-group kernel requirement.**

### New offline OCI process identity gate

A first-party, no-execution checker, [`check-oci-identity.cjs`](../tools/security-audit-pilot/check-oci-identity.cjs), now rejects any OCI `process.user.additionalGids` other than an **explicit empty array**, including the Moby-style primary-GID duplicate. It also requires exact non-root numeric credentials, private user/PID/mount/network/IPC/UTS/cgroup namespaces, non-root outside user and group maps covering the process, all five capability sets empty, `noNewPrivileges`, a non-unconfined AppArmor request, a deny-by-default seccomp declaration, exact first-party Node startup, restricted environment and a read-only root. The only input is a bounded, no-follow, descriptor-read OCI `config.json`. The checker **never runs an OCI runtime or modifies a bundle**. Its result is labeled `OCI STATIC IDENTITY MATCH ONLY`, not runtime validation.

At [Node CI run 42621144506](https://github.com/GoreeCloud/wardveil/actions/runs/42621144506), **275/275 first-party Node tests passed**, including new negative OCI identity tests and a regression that locks the hosted smoke's strict group rejection. Go formatting/vet/race, pinned public Cloudflare file bytes and editorial checks passed separately on that code revision. As before, the independent Docker host and runtime acceptance checks **remain red by design**.

### Required next architecture decision

The current Docker create/run pathway cannot satisfy the strict zero-group requirement merely through `--user UID:GID` and an empty `GroupAdd`. A candidate **separately reviewed OCI-runtime path** must demonstrate that the actual `process.user.additionalGids` is empty *without* gaining initial privilege, bypassing AppArmor/seccomp, altering the policy, or sharing host namespaces. A static spec match is insufficient; a disposable runtime must verify actual `/proc/<pid>/status`, UID/GID maps, namespace inodes, mounts, cgroups, network isolation and cleanup. Any runtime change requires matching first-party host-witness, build provenance, privacy review and rollback gates. **No alternative runtime is implemented, launched, accepted or deployed by this change.**

## Unresolved acceptance requirements

1. A demonstrably disposable, independently owned or approved Linux host with **effective Docker user-namespace remapping**, AppArmor enforcement, cgroup v2 CPU/memory/PID limits, and restrictive seccomp. Docker [userns-remap](https://docs.docker.com/engine/security/userns-remap/) is not equivalent to merely setting `UsernsMode` to an empty string; rootless Docker alone does not meet this profile's AppArmor requirement.
2. An independently reviewed, pinned, immutable image build; matching approved registry manifest and local image ID; source mount permissions and recursive read-only behavior; protected first-party probe SHA-256 and explicit ephemeral-host cleanup/recovery.
3. Resolve the now-confirmed **primary GID duplicated in Docker's supplementary group list** (runs 42559488217 and 42620805738) **without weakening the zero-supplementary-group policy**. The new OCI-spec identity gate provides offline validation for a future separately reviewed OCI-native runtime; it does not make the Docker path acceptable. For an exact Wardveil Node profile, independently inspect the proposed runtime, trust its immutable image, and verify its host/process semantics before first start.
4. The in-container `runtime-probe.cjs --witness-window=90` and separate host-side `host-witness.cjs` must **both** pass on the identical process, with actual kernel namespace identities, UID/GID mappings, AppArmor, seccomp, mounts, network interfaces, and cgroups independently confirmed.
5. Independent verification of effective network egress denial, mount subtrees, process resource limits, image/probe provenance, failure recovery, privacy/retention boundaries and audit-agent execution prohibition. Only after all gates pass could an optional Cloudflare source audit be considered for separate authorization.

**Release disposition:** [Draft PR #24](https://github.com/GoreeCloud/wardveil/pull/24) remains unmerged; the existing Todoist runtime-acceptance task must remain open. Neither a working isolated namespace nor passing synthetic Node tests certifies the full runtime sandbox. Do not run third-party agents on a laptop, VPS, production host, or this unverified CI runner.
