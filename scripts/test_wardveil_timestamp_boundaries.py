#!/usr/bin/env python3
"""Regression sweep for Wardveil timezone-normalization failure containment."""

from __future__ import annotations

import sys
from datetime import datetime, tzinfo
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.wardveil_audit_ledger_v2 import _utc as audit_utc
from reference.wardveil_execution_reconciliation import _utc as reconciliation_utc
from reference.wardveil_incident_v2 import _utc as incident_utc
from reference.wardveil_mesh_evidence import (
    _evaluation_time as mesh_evaluation_time,
    _parse_timestamp as mesh_parse_timestamp,
)
from reference.wardveil_mesh_refresh_handoff import _utc as refresh_handoff_utc
from reference.wardveil_mesh_refresh_response import _utc as refresh_response_utc
from reference.wardveil_mesh_runtime_acceptance import (
    _evaluation_time as mesh_runtime_evaluation_time,
    _parse_timestamp as mesh_runtime_parse_timestamp,
)
from reference.wardveil_persistence import _utc as persistence_utc
from reference.wardveil_platform_adoption_governance_v1 import _timestamp as adoption_timestamp
from reference.wardveil_protect import _parse_time as protect_parse_time
from reference.wardveil_quarantine_object_v2 import _utc as quarantine_utc
from reference.wardveil_scan_replay import _epoch_microseconds
from reference.wardveil_security_center_v2 import _parse_time as security_center_parse_time
from reference.wardveil_service_identity import _now as identity_now
from reference.wardveil_service_identity import _parse_time as identity_parse_time


LOW = datetime.fromisoformat("0001-01-01T00:00:00+01:00")
HIGH = datetime.fromisoformat("9999-12-31T23:59:59-01:00")
LOW_TEXT = "0001-01-01T00:00:00+01:00"
HIGH_TEXT = "9999-12-31T23:59:59-01:00"


class PseudoAwareTimezone(tzinfo):
    def utcoffset(self, value):
        return None


PSEUDO_AWARE = datetime(2026, 9, 27, 12, 0, tzinfo=PseudoAwareTimezone())


def expect_value_error(label: str, function) -> None:
    try:
        function()
    except ValueError:
        return
    raise AssertionError(f"{label} must reject unsupported UTC normalization range")


def main() -> int:
    for label, function in (
        ("audit", lambda: audit_utc(LOW)),
        ("incident", lambda: incident_utc(HIGH)),
        ("persistence", lambda: persistence_utc(LOW)),
        ("quarantine", lambda: quarantine_utc(HIGH)),
        ("execution reconciliation", lambda: reconciliation_utc(LOW)),
        ("mesh evidence parse", lambda: mesh_parse_timestamp(HIGH_TEXT, "observed_at")),
        ("mesh evidence evaluation", lambda: mesh_evaluation_time(LOW)),
        ("mesh runtime parse", lambda: mesh_runtime_parse_timestamp(LOW_TEXT, "collected_at")),
        ("mesh runtime evaluation", lambda: mesh_runtime_evaluation_time(HIGH)),
        ("platform adoption", lambda: adoption_timestamp(HIGH_TEXT, "observed_at")),
        ("security center", lambda: security_center_parse_time(LOW_TEXT)),
        ("service identity now", lambda: identity_now(HIGH)),
        ("mesh refresh handoff", lambda: refresh_handoff_utc(LOW, "requested_at")),
        ("mesh refresh response", lambda: refresh_response_utc(HIGH, "responded_at")),
        ("scan replay", lambda: _epoch_microseconds(LOW)),
    ):
        expect_value_error(label, function)

    for label, function in (
        ("mesh evidence pseudo-aware", lambda: mesh_evaluation_time(PSEUDO_AWARE)),
        ("mesh runtime pseudo-aware", lambda: mesh_runtime_evaluation_time(PSEUDO_AWARE)),
        ("mesh refresh handoff pseudo-aware", lambda: refresh_handoff_utc(PSEUDO_AWARE, "requested_at")),
        ("mesh refresh response pseudo-aware", lambda: refresh_response_utc(PSEUDO_AWARE, "responded_at")),
    ):
        expect_value_error(label, function)

    assert protect_parse_time(LOW_TEXT) is None
    assert protect_parse_time(HIGH_TEXT) is None
    assert identity_parse_time(LOW_TEXT) is None
    assert identity_parse_time(HIGH_TEXT) is None

    print("Wardveil timestamp boundary containment tests passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
