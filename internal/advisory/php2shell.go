// Package advisory provides offline, non-authoritative security triage helpers.
// It does not discover runtimes, inspect hosts, confirm vendor backports,
// scan for compromise, or change a system's security posture.
package advisory

import (
	"strconv"
	"strings"
)

// PHPRuntime describes a caller-supplied observation, not an authenticated
// host inventory or evidence that this binary is actually serving requests.
type PHPRuntime struct {
	Version string `json:"version"`
	Role    string `json:"role"` // web, cli, or unknown
}

// PHPAssessment intentionally excludes hostnames, paths, arguments and raw
// inventory fields; its index refers only to the caller's input ordering.
type PHPAssessment struct {
	Index      int    `json:"index"`
	PatchState string `json:"patch_state"`
	RoleState  string `json:"role_state"`
	Triage     string `json:"triage"`
}

func strictPHPVersion(version string) (int, int, int, bool) {
	if len(version) < 5 || len(version) > 12 {
		return 0, 0, 0, false
	}
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return 0, 0, 0, false
	}
	var numbers [3]int
	for i, part := range parts {
		if len(part) == 0 || len(part) > 3 || len(part) > 1 && part[0] == '0' {
			return 0, 0, 0, false
		}
		for _, ch := range part {
			if ch < '0' || ch > '9' {
				return 0, 0, 0, false
			}
		}
		value, err := strconv.Atoi(part)
		if err != nil {
			return 0, 0, 0, false
		}
		numbers[i] = value
	}
	return numbers[0], numbers[1], numbers[2], true
}

// PHP2ShellAssessment applies October 21, 2026 upstream PHP release thresholds
// for CVE-2026-109618 / CVE-2026-109619. A version comparison never verifies
// an actual running worker, vendor backport, current exposure, or compromise.
func PHP2ShellAssessment(input PHPRuntime, index int) PHPAssessment {
	result := PHPAssessment{Index: index, RoleState: input.Role}
	switch input.Role {
	case "web", "cli", "unknown":
	default:
		result.RoleState = "invalid"
	}
	major, minor, patch, valid := strictPHPVersion(input.Version)
	switch {
	case !valid:
		result.PatchState = "invalid_version"
	case major == 8 && minor >= 2 && minor <= 5:
		cutoff := map[int]int{2: 35, 3: 36, 4: 27, 5: 12}[minor]
		if patch >= cutoff {
			result.PatchState = "upstream_fixed_threshold_met"
		} else {
			result.PatchState = "below_upstream_fix_threshold"
		}
	case major == 8 && minor <= 1 || major == 5 || major == 7:
		result.PatchState = "legacy_or_vendor_specific"
	default:
		result.PatchState = "unrecognized_branch"
	}
	switch {
	case result.RoleState == "invalid" || result.PatchState == "invalid_version":
		result.Triage = "verify_inventory"
	case result.RoleState == "web" &&
		(result.PatchState == "below_upstream_fix_threshold" || result.PatchState == "legacy_or_vendor_specific"):
		result.Triage = "urgent_verify_patch"
	case result.RoleState == "unknown":
		result.Triage = "verify_web_exposure"
	case result.PatchState == "below_upstream_fix_threshold" || result.PatchState == "legacy_or_vendor_specific":
		result.Triage = "verify_vendor_patch"
	default:
		result.Triage = "verify_running_runtime"
	}
	return result
}
