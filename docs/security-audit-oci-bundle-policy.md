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

A successful result says **OCI STATIC IDENTITY MATCH ONLY** or **OCI STATIC BUNDLE POLICY MATCH ONLY**. It does not certify any bytes within `rootfs`, symlink descendants, host permissions, kernel enforcement or the integrity of the runtime binary. The second tool currently checks proposed mount source *strings*, not the source inode or whether a host source mount is already exposed.

## Release gates not met

Before executing even a first-party probe under an OCI-native runtime, independently review the runtime binary and its full dependency/supply chain, the rootfs contents, the immutable first-party probe hash, the OCI spec, the host system, AppArmor and seccomp *effective policy*, user namespace mappings, cgroup v2 resource enforcement, recursive mount restrictions, real network egress denial, and protected host-witness exchange. Scope any trial to a separately approved disposable nonproduction Linux host. Capture a reproducible failure category and securely clean up only trial-owned resources. A successful static bundle check never overrides a failed kernel probe.

**Do not run the Cloudflare agent, target-controlled code, or this unverified OCI configuration on a connected laptop, VPS, production server or shared environment.** Keep PR #24 draft and the existing Todoist acceptance task open until the full runtime and GoreeShield privacy gates pass.
