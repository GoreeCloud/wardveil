#!/usr/bin/env python3
"""Run the authenticated loopback Wardveil Scan HTTP service."""

from __future__ import annotations

import argparse
import os
import signal
import sys
import threading

from reference.wardveil_scan_service import (
    DEFAULT_SCAN_SERVICE_PORT,
    LOOPBACK_HOST,
    WardveilScanService,
    build_http_server,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--port",
        type=int,
        default=int(
            os.environ.get("WARDVEIL_SCAN_SERVICE_PORT", str(DEFAULT_SCAN_SERVICE_PORT))
        ),
    )
    args = parser.parse_args()

    token = os.environ.get("WARDVEIL_SCAN_SERVICE_TOKEN", "")
    try:
        service = WardveilScanService()
        server = build_http_server(service, token, port=args.port)
    except (TypeError, ValueError) as exc:
        print(f"Wardveil Scan service configuration rejected: {exc}", file=sys.stderr)
        return 2

    def stop(_signum: int, _frame: object) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    print(
        f"Wardveil Scan authenticated transport listening on {LOOPBACK_HOST}:{args.port}",
        file=sys.stderr,
    )
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
