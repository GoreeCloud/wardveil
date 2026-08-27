# Wardveil ClamAV Runtime Deployment

This directory provides a deployment baseline for the replaceable ClamAV engine beneath Wardveil Scan. It is source-controlled infrastructure guidance, not evidence that a production scanner is already deployed or accepted.

## Baseline

`compose.yaml` runs the official ClamAV 1.4 LTS feature image and persists the signature database in a named volume. The `clamd` TCP listener is published only on loopback by default. Do not change the binding to a public interface.

For same-host native installations, a local Unix socket remains preferred when it can be shared safely with the Wardveil scanner service. For container deployments, loopback TCP is the baseline supplied here. Cross-host scanner traffic requires a separate authenticated and encrypted private service boundary; the raw `clamd` protocol must not be treated as a public API.

## Configuration

Copy `.env.example` to an untracked `.env` file only on the deployment host and adjust non-secret runtime values as needed. Repository policy already ignores `.env` files. Do not commit credentials, private infrastructure details, or unrestricted diagnostics.

The reference runtime loader recognizes:

- `WARDVEIL_CLAMAV_TCP_HOST` or `WARDVEIL_CLAMAV_UNIX_SOCKET`;
- `WARDVEIL_CLAMAV_PORT`;
- `WARDVEIL_CLAMAV_TIMEOUT_SECONDS`;
- `WARDVEIL_CLAMAV_MAX_STREAM_BYTES`;
- `WARDVEIL_CLAMAV_CHUNK_BYTES`;
- `WARDVEIL_CLAMAV_MAX_SIGNATURE_AGE_HOURS`;
- `WARDVEIL_CLAMAV_HEALTH_VALIDITY_MINUTES`;
- `WARDVEIL_CLAMAV_MAX_SCAN_ERROR_RATE`;
- `WARDVEIL_CLAMAV_MIN_ERROR_RATE_SAMPLES`.

## Start the scanner

From this directory:

```bash
docker compose --env-file .env up -d
```

The image is responsible for `clamd` and signature-update behavior. The persistent `/var/lib/clamav` volume prevents every container replacement from starting without an existing local database.

## Health evidence

Run the Wardveil collector from the repository root on a host that can reach the configured scanner:

```bash
python3 scripts/collect_wardveil_clamav_health.py
```

The collector emits data-minimized JSON containing daemon reachability, engine/database versions, loaded database timestamp, signature freshness, configured scan limit, transport class, and clean-verdict eligibility. It deliberately omits the actual scanner endpoint and socket path.

Use `--require-healthy` in readiness checks when a non-healthy scanner should fail the check:

```bash
python3 scripts/collect_wardveil_clamav_health.py --require-healthy
```

## Clean-verdict gate

A successful ClamAV `OK` response is not sufficient by itself for Wardveil to preserve a `clean` scan result. Wardveil also requires current acceptable scanner-health evidence. Stale, unavailable, future-dated, or otherwise unverified signature evidence downgrades a would-be clean result to `unknown`.

A positive malware signature match remains a malicious finding even if runtime health is degraded. Degraded health must not erase positive threat evidence; it only prevents stale or incomplete scanner state from producing false reassurance.

## Runtime acceptance

Production acceptance remains `unaccepted` until the evidence listed in `contracts/wardveil.clamav.runtime-acceptance.json` is collected for the deployed environment. At minimum this includes current daemon/signature evidence, a controlled EICAR test, a clean control, fail-closed error behavior, at least one application consumer, and evidence that authorized quarantine execution works where the product claims it.

Health alone is not a broad Wardveil protection claim. The health record may describe the narrow scanner-control scope as healthy, but `claim.protected_by_wardveil` remains false until a separate application- or service-specific protection scope is backed by the required authoritative evidence.
