#!/usr/bin/env bash
# Opt-in protocol check against a real, isolated ClamAV using synthetic fixtures.
# No public listener, host scanning, image download, or production service changes.
set -euo pipefail
for tool in go podman python3 mktemp; do
  command -v "$tool" >/dev/null || { echo "Missing $tool" >&2; exit 2; }
done
if [[ "$(podman info --format '{{.Host.Security.Rootless}}')" != "true" ]]; then
  echo "Rootless Podman is required" >&2
  exit 2
fi
image="docker.io/clamav/clamav:1.4_base"
if ! podman image exists "$image"; then
  echo "Approved image not preinstalled; refusing automatic download: $image" >&2
  exit 2
fi
lab="$(mktemp -d /tmp/wardveil-clamd-lab.XXXXXX)"
container_id=""
cleanup() {
  if [[ -n "$container_id" ]]; then
    podman stop --time 3 "$container_id" >/dev/null 2>&1 || true
  fi
  if [[ "$lab" == /tmp/wardveil-clamd-lab.* && -d "$lab" ]]; then
    rm -rf -- "$lab"
  fi
}
trap cleanup EXIT

python3 - "$lab" <<'PY'
import hashlib
import sys
from pathlib import Path
root = Path(sys.argv[1])
(root / "db").mkdir(mode=0o700)
fixture = b"wardveil-integration-test-detection-fixture-2026\n"
(root / "db" / "wardveil.hdb").write_text(
    f"{hashlib.md5(fixture).hexdigest()}:{len(fixture)}:Wardveil.Test.Fixture\n"
)
(root / "clamd.conf").write_text(
    "Foreground yes\n"
    "LocalSocket /work/clamd.sock\n"
    "LocalSocketMode 600\n"
    "DatabaseDirectory /work/db\n"
    "TemporaryDirectory /tmp\n"
    "MaxThreads 1\n"
    "MaxQueue 2\n"
    "StreamMaxLength 8M\n"
    "MaxScanSize 8M\n"
    "MaxFileSize 8M\n"
    "MaxRecursion 4\n"
    "MaxFiles 50\n"
    "ReadTimeout 15\n"
    "CommandReadTimeout 10\n"
)
PY
container_id="$(podman run --pull=never --detach --rm \
  --network=none --cap-drop=ALL --security-opt=no-new-privileges \
  --memory=512m --pids-limit=32 --cpus=1 --read-only \
  --tmpfs /tmp:rw,nosuid,noexec,size=64m --userns=keep-id \
  --user "$(id -u):$(id -g)" \
  --mount "type=bind,src=$lab,dst=/work" \
  --entrypoint /usr/sbin/clamd "$image" --config-file=/work/clamd.conf)"

ready=0
for _ in {1..80}; do
  if [[ -S "$lab/clamd.sock" ]]; then
    ready=1
    break
  fi
  if ! podman container exists "$container_id"; then break; fi
  sleep 0.25
done
if [[ "$ready" != 1 ]]; then
  podman logs --tail 30 "$container_id" >&2 || true
  echo "Test daemon did not become ready" >&2
  exit 1
fi

echo "Testing the real ClamAV daemon using synthetic fixtures only."
WARDVEIL_CLAMD_TEST_SOCKET="$lab/clamd.sock" \
  go test -v -count=1 -run '^Test(ClamdLiveEngine|CoordinatorLiveClamd)$' ./internal/scan
echo "Real-daemon smoke check passed; stopping disposable test service."
