# Wardveil Scan — Pinned Private Journal Directory Handles (Development)

| Property | Verified or planned status |
| --- | --- |
| Scope | `internal/scan/private_journal_linux.go`, `admission.go`, `advice_store.go` |
| Stage | Development only; **not deployed**, no production source owner or scanner |
| Host | Linux local filesystem; other operating systems explicitly return an unsupported-journal error |
| Updated | November 7, 2026 |
| References | [Lease admission](scan-admission.md), [private advice receipts](scan-advice-receipts.md), [scan coordinator](scan-coordinator.md) |

## Threat and trust boundary

Before this change, `FileAdmission.Reserve` and `FileAdviceRecorder.RecordAdvice` checked the configured private directory using `Lstat`, but subsequently reopened its path via `os.OpenFile` and `os.Open`. `ReadReceipt` similarly validated a receipt with `Lstat` and then followed its pathname using `os.ReadFile`. A directory or record entry replaced in the interval could redirect a write, fsync or read. This matters especially during misconfiguration, a host compromise, or when an operator accidentally places a journal beneath a writable parent.

The journal path is **trusted administrator configuration**, never an upload or scan request parameter. Hardening this local reference does not make an attacker-controlled parent safe, remove lease/retention obligations, or protect against malicious administrators with filesystem write access.

## Implemented Linux controls

1. `openPrivateJournalDirectory` uses `open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)`, validates `fstat` permissions of the **opened descriptor**, and checks that `Lstat` of the configured path still identifies the same private directory inode. No final-component symlink is accepted.
2. Both admission and receipt creation are now performed through `openat(dirfd, fixed_filename, O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600)` rather than reopening an absolute pathname. The basename is checked to reject separators, traversal, NUL, empty and dot components. The only admitted basenames come from deterministic SHA-256 fingerprints plus known extensions, not untrusted file paths.
3. The file is fsynced and closed, the **same verified directory descriptor** is fsynced, and the configured path is compared with the opened inode again before returning success. If the path changed, the outcome remains **uncertain and fail-closed**; no marker is deleted or retried automatically.
4. Receipt recovery opens via `openat(dirfd, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)`. It uses the **opened file's fstat**, requiring a regular non-group/world-readable file with a bounded size and exactly one hard link. The bytes are bounded and read through that descriptor, checked against the opened file's expected size and metadata, and passed to the existing strict JSON/lease/verdict validation.
5. Non-Linux builds explicitly refuse private journal operation instead of silently falling back to path-following APIs. This is a **Linux-only reference**, not cross-platform persistent storage.

Both journals preserve the previous semantics: create-exclusively, reject duplicates and incomplete crash markers, minimize stored metadata, return errors on uncertain durability, and **never release, delete, publish or grant access to the owner-controlled source object**. Any clean result remains eligible for **owner review only**.

## Tested behavior

The Linux test suite includes deterministic checks for:

- Holding an opened directory descriptor, renaming the configured directory and replacing its pathname with a symlink to another private directory: **no redirected record write or read**.
- Existing symlinked record: recovery refuses to follow the link, and create-exclusive commit refuses to overwrite it.
- Existing record with an additional hard link: read refuses unexpected link count.
- Slash, backslash, dot, traversal and empty record names: rejected before any syscall on the directory entry.
- Permission drift from private to group/world accessible: rejected for both create and read.
- Source-level `FileAdmission` and `FileAdviceRecorder`: rejection when their configured directories are replaced with symlinks.
- Successful private create/readback and duplicate rejection remain functional.

The authorized Linux development checkout passed `GOMAXPROCS=2 go test -race -p 1 ./... -count=1`, `GOMAXPROCS=2 go vet ./...`, `git diff --check`, and `gofmt` checks (exit 0). No real user content, VPS, production service or live permissions were touched. The previous real ClamAV synthetic integration belongs to PR #18 and is **not** asserted as a new run for this patch.

## Residual risks and operator gates

- **Parent pathname is still administrator-trusted.** `O_NOFOLLOW` applies to the final component; ancestor symlink resolution, malicious parent writers, concurrent parent renames and path swaps immediately *after* the last identity check are not eliminated. Keep all path components under trusted, access-controlled ownership with appropriate sticky-bit and least-privilege rules. A stronger production design may retain an fd for the service lifetime and pin parent inodes, or use `openat2` resolution policy after Linux compatibility assessment.
- **Host filesystem guarantees matter.** This is for a trusted local filesystem that honors exclusive creates and fsync semantics; network mounts, rollback of old snapshots, storage failure and crash recovery require validation. A successful syscall is not proof of power-loss durability on every storage stack.
- **Tamper evidence is not added.** An authorized attacker or compromised local host could overwrite receipts. Receipt SHA-256 fingerprints identify correlation metadata but are not MACs or authenticated audit signatures.
- **Retention remains undefined.** Neither markers nor receipts are automatically deleted. Monitor capacity, protect backups, document authorized retention, and define an operator-approved recovery and lease reissue flow.
- **The real integration is still missing.** No GoreeCloud Identity credential adapter, authenticated owner-held source API, global queue or lease registry, source-owner release policy, full current ClamAV signatures/FreshClam CLD chain or approved VPS deployment exists in this change.

Keep [Wardveil Scan MVP issue #2](https://github.com/GoreeCloud/wardveil/issues/2) open and preserve the draft review chain. This is a targeted directory I/O safety improvement only.
