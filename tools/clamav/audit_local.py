#!/usr/bin/env python3
"""Read-only local ClamAV backend audit; never scans files or changes Docker."""
import argparse
from datetime import datetime, timedelta, timezone
import json
import re
import subprocess
import sys

CONTAINER = "wardveil-clamav-clamd-1"
IMAGE = ("docker.io/clamav/clamav:1.5.4@"
         "sha256:ed2ee243029c1f3c2e13c1eadd835fbca239bbbb80bbde06627f7676a17314f2")
VOLUME = "wardveil_clamav_signatures"
NETWORK = "wardveil_clamav_signature_egress"
MAX_AGE_HOURS = 72
MONTHS = {name: i for i, name in enumerate(
    "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}


def run_local(*args):
    """No shell, no network clients, no secret-bearing output."""
    try:
        completed = subprocess.run(
            ["docker", *args], capture_output=True, text=True,
            timeout=25, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("DOCKER_COMMAND_UNAVAILABLE") from None
    if completed.returncode:
        raise RuntimeError("DOCKER_COMMAND_FAILED")
    return completed.stdout.strip()


def parse_daily_info(info, now):
    """Require verified, unique daily metadata. Treat unknown formats as unready."""
    lines = info.splitlines()
    if lines.count("Verification OK.") != 1:
        raise ValueError("SIGNATURE_VERIFICATION_FAILED")
    version = [s.removeprefix("Version: ") for s in lines
               if s.startswith("Version: ")]
    build = [s.removeprefix("Build time: ") for s in lines
             if s.startswith("Build time: ")]
    if len(version) != 1 or not re.fullmatch(r"[1-9][0-9]{0,8}", version[0]):
        raise ValueError("INVALID_SIGNATURE_VERSION")
    if len(build) != 1:
        raise ValueError("INVALID_SIGNATURE_BUILD_TIME")
    match = re.fullmatch(
        r"([0-9]{1,2}) ([A-Za-z]{3}) ([0-9]{4}) ([0-9]{2}):([0-9]{2}) ([+-])([0-9]{2})([0-9]{2})",
        build[0])
    if match is None:
        raise ValueError("INVALID_SIGNATURE_BUILD_TIME")
    day, mon, year, hour, minute, sign, tzhr, tzmin = match.groups()
    month = MONTHS.get(mon)
    if month is None or int(tzhr) > 23 or int(tzmin) > 59:
        raise ValueError("INVALID_SIGNATURE_BUILD_TIME")
    direction = 1 if sign == "+" else -1
    offset = timedelta(hours=int(tzhr), minutes=int(tzmin)) * direction
    try:
        stamp = datetime(int(year), month, int(day), int(hour), int(minute),
                         tzinfo=timezone(offset))
    except (ValueError, OverflowError):
        raise ValueError("INVALID_SIGNATURE_BUILD_TIME") from None
    age_hours = (now - stamp).total_seconds() / 3600
    if age_hours < -(5.0 / 60):
        raise ValueError("FUTURE_SIGNATURE_BUILD_TIME")
    if age_hours > MAX_AGE_HOURS:
        raise ValueError("SIGNATURES_TOO_OLD")
    return int(version[0]), round(age_hours, 2)


def audit_snapshot(state, engine, database, updater, now):
    """Pure verification function; output contains whitelisted facts only."""
    errors = []
    config = state.get("Config") or {}
    host = state.get("HostConfig") or {}
    runtime = state.get("State") or {}
    network = state.get("NetworkSettings") or {}
    if state.get("Name") != "/" + CONTAINER:
        errors.append("CONTAINER_IDENTITY_MISMATCH")
    if config.get("Image") != IMAGE:
        errors.append("IMAGE_DIGEST_MISMATCH")
    if runtime.get("Status") != "running" or (runtime.get("Health") or {}).get("Status") != "healthy":
        errors.append("DAEMON_NOT_HEALTHY")
    if state.get("RestartCount") != 0:
        errors.append("UNEXPECTED_RESTARTS")
    if host.get("PortBindings") or any(v for v in (network.get("Ports") or {}).values()):
        errors.append("HOST_PORT_PUBLISHED")
    if set((network.get("Networks") or {}).keys()) != {NETWORK}:
        errors.append("UNEXPECTED_NETWORK_ATTACHMENT")
    if config.get("User") != "clamav" or host.get("Privileged") is not False:
        errors.append("UNSAFE_EXECUTION_IDENTITY")
    if not host.get("ReadonlyRootfs") or "ALL" not in (host.get("CapDrop") or []):
        errors.append("UNSAFE_FILESYSTEM_OR_CAPABILITIES")
    if "no-new-privileges:true" not in (host.get("SecurityOpt") or []):
        errors.append("PRIVILEGE_ESCALATION_NOT_DISABLED")
    if host.get("Memory") != 4 * 1024**3 or not 0 < (host.get("PidsLimit") or 0) <= 64:
        errors.append("RESOURCE_LIMIT_MISMATCH")
    mounts = state.get("Mounts") or []
    if host.get("Binds") or len(mounts) != 1 or not all(
        x.get("Type") == "volume" and x.get("Name") == VOLUME
        and x.get("Destination") == "/var/lib/clamav" for x in mounts
    ):
        errors.append("UNEXPECTED_FILESYSTEM_MOUNT")
    if not updater:
        errors.append("SIGNATURE_UPDATER_NOT_RUNNING")
    loaded = None
    match = re.fullmatch(r"ClamAV 1\.5\.4/([0-9]{1,9})/[^\n]+", engine.strip())
    if match:
        loaded = int(match.group(1))
    else:
        errors.append("INVALID_LOADED_ENGINE_VERSION")
    installed, age = None, None
    try:
        installed, age = parse_daily_info(database, now)
    except ValueError as exc:
        errors.append(str(exc))
    if installed is not None and loaded is not None and installed != loaded:
        errors.append("SIGNATURE_GENERATION_MISMATCH")
    return {
        "state": "READY" if not errors else "UNREADY",
        "observed_at": now.isoformat(),
        "engine_daily_version": loaded,
        "verified_disk_daily_version": installed,
        "daily_age_hours": age,
        "freshclam_running": bool(updater),
        "reasons": sorted(set(errors)),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true",
                        help="exit nonzero unless all read-only checks pass")
    args = parser.parse_args()
    now = datetime.now(timezone.utc)
    try:
        objects = json.loads(run_local("inspect", CONTAINER))
        if not isinstance(objects, list) or len(objects) != 1:
            raise RuntimeError("AMBIGUOUS_CONTAINER_INSPECT")
        engine = run_local("exec", CONTAINER, "clamdscan", "--version")
        database = run_local("exec", CONTAINER, "sigtool", "--info",
                             "/var/lib/clamav/daily.cld")
        try:
            run_local("exec", CONTAINER, "pidof", "freshclam")
            updater = True
        except RuntimeError:
            updater = False
        result = audit_snapshot(objects[0], engine, database, updater, now)
    except (RuntimeError, ValueError, json.JSONDecodeError):
        result = {"state": "UNREADY", "observed_at": now.isoformat(),
                  "reasons": ["BACKEND_AUDIT_UNAVAILABLE"]}
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["state"] == "READY" else 1


if __name__ == "__main__":
    sys.exit(main())
