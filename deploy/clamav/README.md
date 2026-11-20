# Wardveil ClamAV — private backend staging

**Status:** A source-controlled, isolated ClamAV backend deployment candidate. Installing the container does **not** install Wardveil Scan, authorize access to customer files, or certify signature readiness. The production Wardveil API, Identity, GoreeShield consent enforcement, source-product hold/release, and authenticated scan workers remain separate development gates.

## Boundary

- Target **VPS Mesh only** under the current infrastructure policy.
- Image: official Cisco Talos `clamav/clamav` Linux/amd64 **1.5.4**, pinned to the independently resolved image manifest digest in `compose.yaml`. Treat its digest as immutable until reviewed and deliberately updated. This is third-party GPLv2 software, **not** relicensed under Wardveil Apache-2.0.
- Run ClamD and FreshClam with the image's official `/init-unprivileged` entrypoint as `clamav`. FreshClam needs outbound network access for public signature updates. The dedicated Compose bridge has **no host port publishing**, and neither ClamD's unauthenticated TCP port 3310 nor milter 7357 is exposed.
- The only persistent content is a named volume for public malware signature databases. Do **not** mount host directories, home folders, upload stores, backups, credentials, browser sessions or customer samples into this container. Docker volume and container control are root-equivalent: restrict operators independently.
- Read-only container root, dropped Linux capabilities, no-new-privileges, bounded RAM/CPU/PIDs and private temporary filesystems reduce but do not eliminate risk. The ClamAV vendor recommends **at least 4 GiB** available to the container because temporary signature-update and reload demand can exceed a previously tested 2 GiB limit; the 4 GiB cap is a ceiling, not reserved memory. Verify host headroom and image release guidance before changing it. The image's default internal ClamD socket is **not** mounted outside the container. No other service is allowed access to this backend until Wardveil's owner-attested and Identity-authorized worker passes its independent integration gates.
- The health check also requires a running **FreshClam updater** process. This detects a crashed updater but cannot alone establish network availability, signature age or downstream alerting. FreshClam failures and lack of reliable notifications still need operational monitoring.
- A ClamD **PING alone is not readiness**: on first start FreshClam may download a new `daily.cld` before the daemon creates its socket, leaving ClamD serving an older database. The private container's health check therefore requires `sigtool --info daily.cld` to report `Verification OK.` and the **loaded ClamD daily version to match the on-disk version**. This is not sufficient to certify the update age, source signing chain, or database policy; those remain separate pre-scan gates. A mismatch must remain unhealthy until a reviewed local reload/safe restart completes.
- **Cloudflare Pages only serves public/user interface assets**. It is not the ClamAV runtime and must not forward, proxy, expose or authenticate directly to ClamD. Do not deploy a placeholder "secure" scan/upload endpoint.
- Clean or detected status is **advisory only**, not a release/unquarantine decision. Missing/stale database, failed scan or degraded health must fail closed at the future source-product owner.

## Admission before initial start

1. Verify the host is VPS Mesh; sufficient RAM, disk, network egress, independent recovery, and existing service continuity. Confirm the Docker/Compose execution path is authorized and do not alter SSH/firewall/DNS.
2. Inspect the official image's origin, image source, upstream licensing, current vulnerabilities and manifest; compare its downloaded digest to the pinned value. Review any security advisories and choose an updated reviewed version where needed.
3. From this exact checked source commit, run `docker compose -f deploy/clamav/compose.yaml config --quiet` and `python3 -m unittest discover -s tests -p 'test_clamav_deploy.py' -v`. The test requires Docker Compose; it never starts a container.
4. **First launch only after admission:** `docker compose -f deploy/clamav/compose.yaml up --detach --no-build --pull never`. Expected non-public network and one new `clamd` container. First signature download/loading can take several minutes and requires verifying a healthy daemon and FreshClam state; a running container is not proof of readiness.
5. Read back `docker compose -f deploy/clamav/compose.yaml ps`, `docker inspect` for actual ports, limits, identity and network, and `docker exec <container> clamdcheck.sh` or `clamdscan` using **only inert synthetic test fixtures**. Never submit personal files or EICAR to an unreviewed production endpoint.
6. Verify public host ports 3310/7357 remain closed, scheduled signature refresh, freshness, disk and memory behavior, and explicit operator notification on stale signatures. Document a rollback path and test it without destroying the signature database. Keep the development-only status until the real owner-held scan handshake and privacy/authorization controls are accepted.

## Read-only private backend audit

The [local Python verifier](../../tools/clamav/audit_local.py) checks the **specific** Wardveil container using local `docker inspect`/`exec` without a shell, network requests, file scans or user-data output. It fails closed on missing/expired (older than 72 hours) or future-dated daily signatures, failed `sigtool --info` verification, loaded database mismatch, missing FreshClam, Docker health failures, published ports, unexpected mounts/networks or security/resource drift. It outputs a small machine-readable JSON status and exits nonzero unless ready. This is **operator-side evidence**, not signed provenance certification or user-level scan admission. Run from a pinned, reviewed source checkout on VPS Mesh with the operator's existing authorized Docker access, for example:

```sh
sg docker -c 'python3 /absolute/approved/wardveil/tools/clamav/audit_local.py --verify'
```

The audit does **not** create an alert, write to Changelogs or Monitor, schedule itself, upload telemetry or administer Docker. Dedicated monitoring, notification routing, durable scan-job audit records, successful signature reload after a later update, restore drills, and independent perimeter tests are **still pending**. Docker-group access is privileged and must not be delegated to Pages Functions or anonymous callers.

## Operational safety and rollback

This compose file has no published port and never modifies an existing GoreeCloud service. For a controlled rollback of this **separate** Compose project, use `docker compose -f deploy/clamav/compose.yaml down` without `--volumes`; removing volumes would lose the downloaded signature cache. Do not use `docker system prune`, delete unrelated Docker volumes, or change the host firewall to make ClamD reachable. A rollback changes only this newly deployed private backend.

**Do not** expose ClamD through Cloudflare, Workers, Pages Functions, public DNS or a port forward. Future Wardveil worker transport should be a private Unix socket or strictly internal authenticated service boundary; ClamD itself does not authenticate clients.

## Dependency / evidence

The bounded Unix-socket scan adapter and development-only owner-held coordinator were ported onto protected main via [PR #37](https://github.com/GoreeCloud/wardveil/pull/37) and [PR #38](https://github.com/GoreeCloud/wardveil/pull/38). The old source branches and their stacked successors remain unmerged and should **not** be merged directly over newer main; reconcile only verified parts of the remaining dependency chain. Neither merged component is wired to a real Identity-authenticated source owner or this private VPS engine. A lab test with synthetic signatures is **not** authoritative verification of FreshClam's real CLD/CVD database. The development-only `VerifiedCVDReadiness` draft deliberately rejects ordinary FreshClam-managed CLD databases; do not bypass it, substitute fake readiness, or promote the API until a reviewed real update-state verifier is implemented.

Primary references: [ClamAV official Docker deployment](https://docs.clamav.net/manual/Installing/Docker.html), [ClamAV security releases](https://www.clamav.net/downloads), [Wardveil scan contract](../../docs/scan-contract.md).
