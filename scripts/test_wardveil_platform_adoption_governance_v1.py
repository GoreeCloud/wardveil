#!/usr/bin/env python3
"""Behavior tests for Wardveil Work Package H."""
from __future__ import annotations

import copy
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.wardveil_platform_adoption_governance_v1 import evaluate_platform_adoption_governance

NOW = "2026-09-10T19:30:00Z"


def base_record() -> dict:
    return {
        "consumer": "goreecloud-wardveil-security",
        "wardveil_contract_version": "next-upgrade-v1",
        "requested_adoption_state": "Source Validated",
        "applicable_capabilities": ["security-state", "audit-evidence"],
        "implemented_capabilities": ["security-state", "audit-evidence"],
        "adoption_evidence": {
            "implementation_evidence_present": True,
            "source_validation_passed": True,
            "runtime_validation_passed": False,
            "production_acceptance_recorded": False,
        },
        "repository_governance": {
            "observed_at": NOW,
            "max_age_seconds": 86400,
            "live_hosting_observation_available": False,
            "pull_request_required": False,
            "required_checks_enforced": False,
            "current_head_or_stale_review_protection": False,
            "force_push_restricted": False,
            "branch_deletion_restricted": False,
            "admin_bypass_bounded": False,
            "codeowners_applicable": True,
            "codeowners_present": True,
        },
    }


def main() -> None:
    current = evaluate_platform_adoption_governance(base_record(), evaluated_at=NOW)
    assert current["adoption"]["requested_state_evidence_complete"] is True
    assert current["repository_governance"]["verified"] is False
    assert current["claim_authority"] is False
    assert "live_repository_governance_unverified" in current["reason_codes"]

    escalated = base_record()
    escalated["requested_adoption_state"] = "Production Accepted"
    result = evaluate_platform_adoption_governance(escalated, evaluated_at=NOW)
    assert result["adoption"]["production_accepted"] is False
    assert "adoption_evidence_missing:Runtime Validated" in result["reason_codes"]
    assert "adoption_evidence_missing:Production Accepted" in result["reason_codes"]

    incomplete = base_record()
    incomplete["implemented_capabilities"] = ["security-state"]
    result = evaluate_platform_adoption_governance(incomplete, evaluated_at=NOW)
    assert result["adoption"]["requested_state_evidence_complete"] is False
    assert "adoption_evidence_missing:applicable_capabilities_incomplete" in result["reason_codes"]

    stale = base_record()
    stale["repository_governance"]["observed_at"] = "2026-08-20T00:00:00Z"
    result = evaluate_platform_adoption_governance(stale, evaluated_at=NOW)
    assert "repository_governance_evidence_stale" in result["reason_codes"]

    governed = base_record()
    governed["requested_adoption_state"] = "Production Accepted"
    governed["adoption_evidence"]["runtime_validation_passed"] = True
    governed["adoption_evidence"]["production_acceptance_recorded"] = True
    governed["repository_governance"]["live_hosting_observation_available"] = True
    for key in (
        "pull_request_required",
        "required_checks_enforced",
        "current_head_or_stale_review_protection",
        "force_push_restricted",
        "branch_deletion_restricted",
        "admin_bypass_bounded",
    ):
        governed["repository_governance"][key] = True
    result = evaluate_platform_adoption_governance(governed, evaluated_at=NOW)
    assert result["adoption"]["production_accepted"] is True
    assert result["claim_authority"] is True

    missing_codeowner = copy.deepcopy(governed)
    missing_codeowner["repository_governance"]["codeowners_present"] = False
    result = evaluate_platform_adoption_governance(missing_codeowner, evaluated_at=NOW)
    assert result["claim_authority"] is False
    assert "codeowners_missing" in result["reason_codes"]

    print("Wardveil platform adoption/governance behavior tests passed")


if __name__ == "__main__":
    main()
