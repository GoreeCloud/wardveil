# Wardveil authenticated Scan service

This deployment surface exposes Wardveil Scan to same-host GoreeCloud consumers without exposing `clamd` itself. It is deliberately loopback-only and requires a bearer token on every scan request.

## Boundary

- HTTP listener: `127.0.0.1:8791` by default.
- Scanner backend: the accepted Wardveil ClamAV runtime configured by `/etc/goreecloud/wardveil/clamav.env`.
- Authentication: `WARDVEIL_SCAN_SERVICE_TOKEN`, minimum 32 bytes.
- Payload: raw resource bytes are supplied to the local service for scanning but are not written to shared evidence records or response metadata.
- Response: canonical Wardveil `scan_finding` with `scan_result`, exact resource identity, SHA-256 binding, evidence references, and bounded validity.
- Claims: installing or starting this service does not by itself satisfy application-consumer integration and does not authorize a Protected by Wardveil claim.

Do not proxy, firewall-publish, Tunnel-publish, or otherwise expose this listener outside loopback. A future cross-host transport requires a separately designed authenticated and encrypted private service boundary.

## Install on an accepted scanner release

The accepted release must contain `reference/wardveil_scan_service.py`, `scripts/serve_wardveil_scan.py`, and this deployment directory.

Create the production environment file without printing its token into logs:

```sh
sudo install -d -m 0750 /etc/goreecloud/wardveil
token="$(openssl rand -hex 32)"
printf 'WARDVEIL_SCAN_SERVICE_TOKEN=%s\nWARDVEIL_SCAN_SERVICE_PORT=8791\n' "$token" \
  | sudo tee /etc/goreecloud/wardveil/scan-service.env >/dev/null
unset token
sudo chmod 0640 /etc/goreecloud/wardveil/scan-service.env
sudo chown root:root /etc/goreecloud/wardveil/scan-service.env
```

Install and start the hardened unit:

```sh
sudo install -m 0644 \
  /opt/goreecloud/wardveil/clamav/current/deployment/scan-service/wardveil-scan.service \
  /etc/systemd/system/wardveil-scan.service
sudo systemctl daemon-reload
sudo systemctl enable --now wardveil-scan.service
```

Verify only the non-sensitive loopback health endpoint:

```sh
curl --fail --silent http://127.0.0.1:8791/healthz
sudo ss -ltnp | grep ':8791'
```

A real application-consumer acceptance run must use the bearer token and the consumer's actual Wardveil integration code. Do not use direct `clamd` access as a substitute.
