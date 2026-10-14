#!/usr/bin/env python3
"""Nonpromoting, bounded historical Workers Logs marker verification.

Never prints raw Cloudflare telemetry, secrets, or received response bodies.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import sys
import urllib.error
import urllib.request

MARKER = re.compile(r"acceptance-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
WORKER = "goreecloud-wardveil-persistence"
FROZEN_REVISION = "cc493530c02925a4404c54d2767c15d9fbfa0835"


def matching_producer(event: object, marker: str) -> bool:
    if not isinstance(event, dict):
        return False
    meta = event.get("$metadata")
    workers = event.get("$workers")
    if not isinstance(meta, dict):
        meta = {}
    if not isinstance(workers, dict):
        workers = {}
    if meta.get("service") != WORKER and workers.get("scriptName") != WORKER:
        return False
    searchable = json.dumps({
        "message": meta.get("message"),
        "error": meta.get("error"),
        "source": event.get("source"),
    }, ensure_ascii=True)
    return marker in searchable


def validate_window(start_text: str, end_text: str) -> tuple[dt.datetime, dt.datetime]:
    def read_utc(text: str) -> dt.datetime:
        value = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
        if value.tzinfo is None or value.utcoffset() != dt.timedelta(0):
            raise ValueError("UTC timezone required")
        return value

    start, end = read_utc(start_text), read_utc(end_text)
    now = dt.datetime.now(dt.timezone.utc)
    if not (dt.timedelta(0) < end - start <= dt.timedelta(minutes=30)):
        raise ValueError("Query window must be positive and <= 30 minutes")
    if start < now - dt.timedelta(days=7) or end > now + dt.timedelta(minutes=2):
        raise ValueError("Query window outside bounded retention/future period")
    return start, end


def self_test() -> None:
    marker = "acceptance-ebb6c624-69dd-4364-bc66-f282b2a6e5e1"
    evidence = {
        "$metadata": {"service": WORKER, "message": '{"event":"wardveil_acceptance_observability_probe","marker":"' + marker + '"}'},
        "source": "synthetic",
    }
    assert matching_producer(evidence, marker)
    assert not matching_producer({**evidence, "$metadata": {"service": "another-worker", "message": marker}}, marker)
    assert not matching_producer({**evidence, "$metadata": {"service": WORKER, "message": "unrelated"}}, marker)
    assert not matching_producer({"$metadata": {"service": WORKER}, "source": {"marker": marker + "x"}}, marker + "missing")
    print("Historical observability local self-test passed; no live acceptance authority.")


def main() -> None:
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return
    if len(sys.argv) != 1:
        raise SystemExit("Usage: verify_cloudflare_historical_observability.py [--self-test]")
    marker = os.environ["WARDVEIL_ACCEPTANCE_MARKER"]
    account = os.environ["CLOUDFLARE_ACCOUNT_ID"]
    token = os.environ.get("CLOUDFLARE_OBSERVABILITY_API_TOKEN", "")
    if not token:
        raise SystemExit("Dedicated Cloudflare observability credential is missing; keep deployment token unchanged")
    if not MARKER.fullmatch(marker) or not re.fullmatch(r"[a-fA-F0-9]{32}", account):
        raise SystemExit("Invalid marker/account input")
    start, end = validate_window(os.environ["WARDVEIL_WINDOW_FROM"], os.environ["WARDVEIL_WINDOW_TO"])

    request_body = {
        "queryId": "wardveil-synthetic-historical-marker-readback",
        "timeframe": {
            "from": int(start.timestamp() * 1000),
            "to": int(end.timestamp() * 1000),
        },
        "parameters": {
            "datasets": ["cloudflare-workers"],
            "needle": {"value": marker, "isRegex": False, "matchCase": True},
            "limit": 25,
        },
        "view": "events",
        "limit": 25,
        "dry": True,
    }
    url = "https://api.cloudflare.com/client/v4/accounts/" + account + "/workers/observability/telemetry/query"
    req = urllib.request.Request(
        url,
        data=json.dumps(request_body).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
            "User-Agent": "GoreeCloud-Wardveil-Bounded-Historical-Readback/1",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=28) as response:
            status = response.status
            data = response.read(1_500_000)
    except urllib.error.HTTPError as error:
        print(json.dumps({
            "kind": "wardveil_historical_log_readback",
            "http_status": error.code,
            "matched": False,
            "possible_observability_permission_gap": error.code == 403,
            "acceptance_authority": False,
        }, sort_keys=True))
        raise SystemExit("Cloudflare historical readback denied or failed; do not broaden the deployment credential automatically")
    except (OSError, TimeoutError):
        raise SystemExit("Cloudflare historical readback transport failed")

    try:
        payload = json.loads(data)
        result = payload["result"]
        events_obj = result["events"]
        events = events_obj["events"]
        run = result["run"]
        if not isinstance(events, list) or len(events) > 25:
            raise ValueError("Invalid or excessive event count")
        if not isinstance(run, dict) or not isinstance(events_obj, dict):
            raise ValueError("Invalid query result shape")
    except (KeyError, TypeError, ValueError):
        raise SystemExit("Cloudflare readback returned an unexpected schema; acceptance not established")

    qualified = [e for e in events if matching_producer(e, marker)]
    success = (
        status == 200
        and payload.get("success") is True
        and run.get("status") == "COMPLETED"
        and bool(qualified)
    )
    print(json.dumps({
        "kind": "wardveil_historical_log_readback",
        "http_status": status,
        "api_success": payload.get("success") is True,
        "query_complete": run.get("status") == "COMPLETED",
        "returned_events": len(events),
        "exact_marker_and_producer_matches": len(qualified),
        "worker": WORKER,
        "seal_revision": FROZEN_REVISION,
        "raw_events_printed_or_uploaded": False,
        "acceptance_authority": False,
        "evidence_status": "observed_nonpromoting" if success else "not_proven",
    }, sort_keys=True))
    if not success:
        raise SystemExit("Stored Workers Logs did not prove the exact acceptance marker and producer identity")


if __name__ == "__main__":
    main()
