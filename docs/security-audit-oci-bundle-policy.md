# Wardveil — proposed OCI bundle policy (static preflight only)

**Status:** Implemented on [draft PR #24](https://github.com/GoreeCloud/wardveil/pull/24), not released or runtime-authorized. This document is a review specification, **not** instructions to launch a container.

## Purpose and authority

The previously observed Docker runtime supplied the process's primary GID a second time as a supplementary group, even with no configured `GroupAdd`. Live independent [evidence](./security-audit-runtime-isolation-evidence.md) confirmed the duplicate and the strict Wardveil kernel probe rejected it. The [Moby OCI source](https://github.com/moby/moby/blob/master/daemon/oci_linux.go) corroborates this implementation behavior. We will **not** weaken `Groups:` being empty merely to make Docker tests green.

To prepare an alternate, separately approved OCI-native execution architecture without running third-party code, Wardveil now uses two independent offline tools:

1. [`check-oci-identity.cjs`](../tools/security-audit-pilot/check-oci-identity.cjs) requires an explicit `process.user.additionalGids: []`, the unprivileged process identity, exact first-party Node probe arguments/environment, no capabilities, private namespace declarations and outside-root user/group mappings.
2. [`check-oci-bundle-policy.cjs`](../tools/security-audit-pilot/check-oci-bundle-policy.cjs) **re-runs the identity gate**, then restricts the bundle's proposed mounts, resources, device policy, hooks, sysctl changes, platform extensions and seccomp declarations.

Both accept a single, absolute, descriptor-safe Linux path to an ordinary, bounded OCI `config.json` file. Both reject symlinked parent/final paths and malformed JSON through the shared source reader. They make **no changes** and cannot create, start, configure or exec a container.

## Reviewed proposal profile

| Control | Offline preflight requirement |
| --- | --- |
| OCI schema | Exactly OCI configuration version `1.1.0`; reject unreviewed version drift and top-level extensions |
| Process | Exactly `/usr/bin/node /opt/wardveil/runtime-probe.cjs --witness-window=90`; UID/GID 65534, explicitly empty `additionalGids`, no-new-privileges, exactly reviewed environment, no tty or additional capabilities |
| Namespace declarations | One fresh each of user, PID, mount, network, IPC, UTS and cgroup; no inherited namespace paths |
| User/GID mappings | Single bounded mapping, covering unprivileged process ID and excluding outside UID/GID 0 |
| Root | Relative `rootfs`, `readonly: true`, no unreviewed root extensions |
| OCI mounts | Exactly `/proc` (read-only proc), `/sys/fs/cgroup` (read-only cgroup2), `/source` (recursive read-only private bind under reviewed prefix), `/scratch` and `/tmp` (small noexec/nosuid/nodev tmpfs); reject extra, stacked, duplicated, writable-source and host-home mounts |
| Mount propagation | Explicit `rprivate`; no unreviewed mounted device nodes or network devices |
| Resource limits | Memory 64–512 MiB, total memory+swap equal to memory limit (no added swap), bounded quota of at most one CPU, PID limit 1–32, an explicit deny-only device cgroup rule |
| Additional settings | No lifecycle hooks, arbitrary annotations, sysctl modifications, unrelated platform/process extensions or unapproved cgroup override fields |
| Seccomp syntax | Explicit `SCMP_ACT_ERRNO` default, x86-64 architecture, and syscall names drawn **only from the fixed 44-name proposed allowlist**. Unreviewed names such as `socket`, `connect`, `execve`, `fork`, `clone`, `clone3`, filesystem mutation, mount, ptrace, BPF, io_uring, and userfaultfd are rejected. No notification listener, unreviewed flags or unknown rule actions |
| Kernel-information paths | Exact reviewed mask list and read-only kernel-control paths |

This proposal intentionally errs on the restrictive side. **It has not been demonstrated that Node can start and run successfully under this exact OCI profile.** In particular, the final seccomp syscall allowlist, the device setup required for runtime stdio, and recursive read-only mount behavior need separate runtime review; restrictions must not be silently relaxed to resolve a failure.

The source of OCI field definitions is the [Open Container Initiative runtime specification](https://github.com/opencontainers/runtime-spec/blob/main/config.md) and its [Linux Go structures](https://github.com/opencontainers/runtime-spec/blob/main/specs-go/config.go). Reading this specification and validating JSON fields do **not** establish that any runtime supports or enforces the proposed values.

## Unresolved execution-model incompatibilities and parser safety

The proposed static seccomp policy is deliberately **not ready for Node execution**. In particular, `execve` and unfiltered `clone`/`clone3` are not approved, whereas normal OCI process startup and Node/libuv may require these operations. An execution-capable, argument-constrained profile would require independent runtime-specific analysis. We must not loosen the allowlist solely to make a green runtime check, and a passing static check must never be treated as evidence that the proposed Node process can start.

The OCI CLI tools now share a first-party **duplicate-member-rejecting JSON parser**. It is applied to exactly the bytes read through the bounded, descriptor-relative Linux file reader; no second pathname-based read occurs. Repeated object keys, including escaped aliases such as `"a"` versus `"\\u0061"`, fail closed. Whitespace and normal formatted JSON remain supported. This is intended to prevent ambiguous OCI configuration evidence in tools with different duplicate-key handling; it is not runtime attestation.

The existing Docker inspection input path retains its earlier JSON parser. The new rejection specifically protects both OCI CLI tools, which analyze pre-execution security-sensitive bundles. The parser has a 64-level structure-depth cap and relies on JSON.parse for syntax validation; the source file reader independently bounds bytes and rejects symlink ancestors, non-regular input and changes observed during read.

## Suggested read-only review procedure

The following commands are *offline static preflight only* and are not authorization to run a process:

```sh
node tools/security-audit-pilot/check-oci-identity.cjs /absolute/path/to/reviewed/config.json
node tools/security-audit-pilot/check-oci-bundle-policy.cjs /absolute/path/to/reviewed/config.json
```

The first two successful results say **OCI STATIC IDENTITY MATCH ONLY** or **OCI STATIC BUNDLE POLICY MATCH ONLY**. Their JSON checks alone cannot certify files within `rootfs`. The separate third gate below can compare rootfs file bytes against a reviewer-supplied manifest, but even a file match does not prove runtime execution, trustworthy manifest authorship, host integrity, kernel enforcement or future immutability. The bundle-policy checker still only checks proposed `/source` bind source *strings*, not the mounted inode or whether other host data is exposed.

## Manifest-pinned read-only OCI rootfs evidence

A third, independent offline checker, [`check-oci-rootfs.cjs`](../tools/security-audit-pilot/check-oci-rootfs.cjs), verifies the **exact file set and bytes** of a proposed root filesystem before any runtime is used. It requires an out-of-band, independently reviewed SHA-256 digest for the **manifest**, not merely a manifest stored beside its own contents.

Manifest schema: `wardveil-oci-rootfs-v1`, with lexicographically ordered, unique `files` entries, each containing exactly `path`, `size`, lowercase SHA-256 `sha256`, and restrictive `mode` (`0444` or `0555`). Required paths are `usr/bin/node` (mode `0555`) and `opt/wardveil/runtime-probe.cjs` (mode `0444`). Additional runtime libraries must be explicitly named and pinned, not inferred. The 512-file manifest limit, 128 MiB per-file limit, 512 MiB aggregate limit, and 12-component path depth are **preflight bounds**, not an assertion that a working Node image fits these limits.

The checker opens every ancestor relative to a Linux directory descriptor with `O_NOFOLLOW`, walks every directory without following symlinks, refuses unlisted files and empty/unlisted directories, and refuses hardlinked, nonregular or writable-by-group/other entries. It hashes actual file contents in bounded chunks and compares file and directory metadata before and after reading to detect observed mutations. It also uses the duplicate-safe parser on the original single bounded manifest-file read. No bundle extraction, chmod, chown, network request, subprocess, or OCI runtime action occurs.

Example (static check only; `REVIEWED_MANIFEST_DIGEST` must be obtained from an independent trusted review):

```sh
node tools/security-audit-pilot/check-oci-rootfs.cjs \
  /absolute/reviewed/rootfs \
  /absolute/reviewed/manifest.json \
  --manifest-sha256 "${REVIEWED_MANIFEST_DIGEST}"
```

A successful result says **ROOTFS STATIC BYTE MATCH ONLY**. An untrusted author can manufacture a manifest and matching digest; consequently a digest becomes meaningful only if the manifest itself is reviewed and pinned independently. This checker does not authenticate OCI binaries, kernel mounts, libraries after validation, memory execution, dynamic-loader behavior, or subsequent image-layer changes. The strict no-symlink profile may reject otherwise legitimate Linux rootfs layouts and must not be relaxed without independent review.

[Exact-code-head CI 42980723870](https://github.com/GoreeCloud/wardveil/actions/runs/42980723870) passed **412/412 Node tests**, Go formatting/vet/race, with [pinned upstream byte verification 42980723892](https://github.com/GoreeCloud/wardveil/actions/runs/42980723892) and [editorial advisory 42980724830](https://github.com/GoreeCloud/wardveil/actions/runs/42980724830) also passing at commit `2d27c869498619ed1d94e320761c5b8457adb19d`. The separate disposable-host and first-party Docker runtime acceptance workflows still failed and must remain release blockers.

## Linked OCI config, manifest and rootfs evidence (November 11, 2026)

The individual OCI identity, bundle-policy and rootfs checks can all pass on **different artifacts**. Their independent success alone does not prove they describe a single reviewed OCI bundle. To prevent accidentally combining unrelated successful reports, the first-party read-only [`check-oci-evidence.cjs`](../tools/security-audit-pilot/check-oci-evidence.cjs) now performs a *linked* check.

It requires (1) a canonical `/absolute/bundle/config.json`, (2) an independently placed `/absolute/reviewer/manifest.json` that is **outside the candidate bundle**, and (3) two independent, lowercase 64-character SHA-256 pins. It hashes the original descriptor-read bytes of both JSON documents, rejects duplicate JSON keys and invalid OCI policies, and derives the rootfs location as **exactly the `rootfs` directory beside that `config.json`**. It then calls the same pinned-byte rootfs verifier. The caller cannot substitute a different `--rootfs` argument. A matching result is `OCI LINKED STATIC EVIDENCE MATCH ONLY`; it does not authenticate the reviewer, the proposed container runtime, or any future filesystem state.

Example (static check only; pins must be supplied from an independent trusted review):

```sh
node tools/security-audit-pilot/check-oci-evidence.cjs \
  /absolute/bundle/config.json \
  /absolute/reviewer/manifest.json \
  --config-sha256 "${REVIEWED_CONFIG_SHA256}" \
  --manifest-sha256 "${REVIEWED_MANIFEST_SHA256}"
```

Separate hardening now inspects the current Linux mount table **before and after** the rootfs scan. It rejects stacked mounts at the rootfs path, any nested mountpoint beneath that path, and a change in the rootfs mount ID between observations. File and directory device IDs must agree with the opened rootfs, and directories may use only reviewed modes `0555` or `0755`, excluding setuid, setgid, sticky and hidden permission bits. Mountinfo parsing has bounded bytes/entries and rejects ambiguous escaped paths. It remains a point-in-time check, not continuous or cryptographically authenticated kernel mount evidence.

**Raw-byte hash correction:** The shared descriptor-safe reader now exposes the actual bounded file bytes to opting-in verification callbacks. Both the manifest verifier and linked bundle tool hash **those bytes**, not decoded-and-reencoded JSON text. A regression test confirms that adding a UTF-8 byte-order mark changes the expected digest, even when decoded JSON fields remain equivalent.

[First-party Node CI on implementing code 42983057911](https://github.com/GoreeCloud/wardveil/actions/runs/42983057911) has independently reported **446/446 passing tests, zero failures/skips**, including positive linked inert fixtures and negative pin, symlink, OCI-policy, missing-file, mountpoint and BOM tests. The full Go job was still finishing when this document revision was authored; do not interpret the Node result as a complete runtime verification. The dedicated host and Docker-runtime workflows continue to fail required isolation controls, and **no OCI-native runtime has been started**.

## Proposed source-bind inode and mount preflight — November 11, 2026

The earlier OCI policy accepted the proposed `/source` bind mount based on its **path string alone**. A new standalone, first-party, read-only [`check-source-mount.cjs`](../tools/security-audit-pilot/check-source-mount.cjs) now inspects a candidate host-side source directory under the fixed `/srv/wardveil-audit-pilot/source/<approved-label>` prefix.

The CLI requires exactly one canonical, lowercase slug directly under that prefix. It opens source path components relative to pinned Linux directory handles with `O_NOFOLLOW`, reads `/proc/self/mountinfo` before and after walking the tree, rejects stacked/nested mounts or a changed root mount ID, and rejects symlinks, hardlinks, device/socket/FIFO entries, hidden names, selected secret/credential-like names and unsafe file/directory modes. It requires regular source files in modes `0444` or `0555` and directories in `0555` or `0755`; the traversal is bounded to 1,024 entries, 8 levels, 16 MiB per file and 128 MiB total by metadata. No file is executed, renamed, deleted or modified.

The CLI emits **SOURCE STATIC MOUNT-PATH MATCH ONLY** when it accepts a path. These are **point-in-time metadata checks**, not source-content hashes, a secret scanner, mount propagation attestation or a guarantee that the OCI runtime actually mounts the checked directory. Owner-writable `0755` directories can also be changed after inspection. Source-file byte provenance, authenticated approved source ownership, and live read-only/recursive bind enforcement remain separate mandatory release gates. This checker is **not yet incorporated into the linked OCI config/rootfs evidence result**, and its standalone success cannot substitute for those gates.

The [implementation test suite](../tools/security-audit-pilot/check-source-mount.test.cjs) uses **only inert temporary fixture trees**, including expected failures for symlinks, hardlinks, forbidden names, unsafe modes and source mount boundaries. [Exact-head foundation CI 42986495718](https://github.com/GoreeCloud/wardveil/actions/runs/42986495718) passed **470/470 Node tests** and Go checks. The two existing real Docker acceptance workflows remained failing as required.

## OCI-native host candidate discovery — no runtime execution

A new PR-scoped [read-only inventory workflow](../.github/workflows/wardveil-oci-runtime-inventory.yml) checks a fresh GitHub-hosted `ubuntu-24.04` VM **without checkout, sudo, package installation, container creation or running `runc`**. [Its first run 42986495891](https://github.com/GoreeCloud/wardveil/actions/runs/42986495891) found Linux x86-64, unified cgroup v2 and its CPU/memory/PID controllers, AppArmor module support, namespace interfaces, and an installed hashable **but independently unreviewed `runc` binary**. The job was successful **as an inventory only**; it does not claim security acceptance, trust, or runtime compatibility.

An independent source-only inspection of the official `opencontainers/runc` repository at tagged release `v1.5.2` found [`libcontainer/init_linux.go`](https://github.com/opencontainers/runc/blob/v1.5.2/libcontainer/init_linux.go), where the implementation invokes `unix.Setgroups(config.AdditionalGroups)` on its permitted Linux path, before setting GID/UID. This is a plausible route to an actually empty supplementary group list **if** the effective runtime applies a vetted empty OCI `additionalGids` array and all other kernel gates pass. It is *not proof* that the GitHub-hosted installed binary matches this version, has authenticated origin, or will safely execute the proposed profile. The untrusted installed runtime is **not executed** by this inventory workflow.

Before a first-party OCI runtime smoke can be authorized, authenticate the installed candidate binary and its dependencies against independently trusted distribution/release evidence; review runtime invocation permissions, userns mappings, AppArmor and seccomp filter effectiveness, private mount and network handling, cgroup resource bounds, immutable first-party rootfs and probe, and exact cleanup behavior. Do not remove the explicit empty supplementary-groups requirement or weaken Wardveil's runtime gate.

## Release gates not met

Before executing even a first-party probe under an OCI-native runtime, independently review the runtime binary and its full dependency/supply chain, the rootfs contents, the immutable first-party probe hash, the OCI spec, the host system, AppArmor and seccomp *effective policy*, user namespace mappings, cgroup v2 resource enforcement, recursive mount restrictions, real network egress denial, and protected host-witness exchange. Scope any trial to a separately approved disposable nonproduction Linux host. Capture a reproducible failure category and securely clean up only trial-owned resources. A successful static bundle check never overrides a failed kernel probe.

**Do not run the Cloudflare agent, target-controlled code, or this unverified OCI configuration on a connected laptop, VPS, production server or shared environment.** Keep PR #24 draft until the full runtime and GoreeShield privacy gates pass. The formerly tracked Todoist task ID was inaccessible (HTTP 404 on November 11, 2026); its acceptance obligation must be reconciled in the authorized task system.
