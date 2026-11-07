package advisory

import (
	"encoding/json"
	"testing"
)

func TestPHP2ShellReleaseThresholds(t *testing.T) {
	cases := []struct {
		version string
		state   string
	}{
		{"8.2.34", "below_upstream_fix_threshold"},
		{"8.2.35", "upstream_fixed_threshold_met"},
		{"8.3.35", "below_upstream_fix_threshold"},
		{"8.3.36", "upstream_fixed_threshold_met"},
		{"8.4.26", "below_upstream_fix_threshold"},
		{"8.4.27", "upstream_fixed_threshold_met"},
		{"8.5.11", "below_upstream_fix_threshold"},
		{"8.5.12", "upstream_fixed_threshold_met"},
		{"8.5.13", "upstream_fixed_threshold_met"},
		{"8.1.34", "legacy_or_vendor_specific"},
		{"7.4.33", "legacy_or_vendor_specific"},
		{"5.6.40", "legacy_or_vendor_specific"},
		{"8.6.0", "unrecognized_branch"},
		{"9.0.0", "unrecognized_branch"},
		{"8.3", "invalid_version"},
		{"PHP 8.4.27", "invalid_version"},
		{"8.4.27-ubuntu1", "invalid_version"},
		{"08.4.27", "invalid_version"},
		{"8.4.27\\n", "invalid_version"},
	}
	for _, tc := range cases {
		t.Run(tc.version, func(t *testing.T) {
			got := PHP2ShellAssessment(PHPRuntime{Version: tc.version, Role: "web"}, 7)
			if got.PatchState != tc.state || got.Index != 7 {
				t.Fatalf("got %#v, want patch state %q and index 7", got, tc.state)
			}
		})
	}
}

func TestPHP2ShellTriageNeverClaimsConfirmedRemediation(t *testing.T) {
	cases := []struct {
		version string
		role    string
		triage  string
	}{
		{"8.4.26", "web", "urgent_verify_patch"},
		{"8.4.26", "cli", "verify_vendor_patch"},
		{"8.4.26", "unknown", "verify_web_exposure"},
		{"8.4.27", "web", "verify_running_runtime"},
		{"8.4.27", "unknown", "verify_web_exposure"},
		{"8.1.34", "web", "urgent_verify_patch"},
		{"8.6.0", "web", "verify_inventory"},
		{"9.0.0", "unknown", "verify_inventory"},
		{"8.4.27", "invalid-role", "verify_inventory"},
		{"bad", "web", "verify_inventory"},
	}
	for _, tc := range cases {
		got := PHP2ShellAssessment(PHPRuntime{Version: tc.version, Role: tc.role}, 0)
		if got.Triage != tc.triage {
			t.Fatalf("%s %s: got %q, want %q", tc.version, tc.role, got.Triage, tc.triage)
		}
	}
}

func TestPHP2ShellOutputMinimizesInputData(t *testing.T) {
	got := PHP2ShellAssessment(PHPRuntime{Version: "8.4.26", Role: "web"}, 0)
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"index":0,"patch_state":"below_upstream_fix_threshold","role_state":"web","triage":"urgent_verify_patch"}` {
		t.Fatalf("unexpected assessment fields: %s", encoded)
	}
}
