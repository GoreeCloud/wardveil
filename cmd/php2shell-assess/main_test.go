package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestBoundedOfflinePHPAssessment(t *testing.T) {
	input := `[{"version":"8.4.26","role":"web"},{"version":"8.4.27","role":"cli"},{"version":"8.4.25","role":"unknown"}]`
	var output bytes.Buffer
	if err := run(strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	var report struct {
		SchemaVersion string `json:"schema_version"`
		Scope         string `json:"scope"`
		Assessments   []struct {
			Index      int    `json:"index"`
			PatchState string `json:"patch_state"`
			Triage     string `json:"triage"`
		} `json:"assessments"`
	}
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != "wardveil.php2shell.advisory.v1" ||
		report.Scope != "offline_non_authoritative_no_host_verification" ||
		len(report.Assessments) != 3 {
		t.Fatalf("unexpected offline report: %+v", report)
	}
	if report.Assessments[0].Index != 0 || report.Assessments[0].Triage != "urgent_verify_patch" ||
		report.Assessments[1].PatchState != "upstream_fixed_threshold_met" ||
		report.Assessments[2].Triage != "verify_web_exposure" {
		t.Fatal("incorrect index, patch threshold or exposure classification")
	}
	if strings.Contains(output.String(), "8.4.26") || strings.Contains(output.String(), "8.4.27") {
		t.Fatal("output must not reprint raw inventory version fields")
	}
}

func TestOfflineInventoryRejectsUntrustedOrAmbiguousInput(t *testing.T) {
	cases := []string{
		`[]`,
		`null`,
		`{}`,
		`[null]`,
		`[{"version":"8.4.27"}]`,
		`[{"role":"web"}]`,
		`[{"version":"8.4.27","role":"web","host":"private"}]`,
		`[{"version":"8.4.27","version":"8.4.26","role":"web"}]`,
		`[{"version":847,"role":"web"}]`,
		`[{"version":"8.4.27","role":null}]`,
		`[{"version":"8.4.27","role":"web"}] {"extra":true}`,
		`[{"version":"8.4.27","role":"web"}] []`,
		`[{"version":"8.4.27","role":"web"}`,
	}
	for _, tc := range cases {
		if _, err := readInventory(strings.NewReader(tc)); err == nil {
			t.Fatalf("malformed inventory accepted: %q", tc)
		}
	}
	if _, err := readInventory(strings.NewReader(strings.Repeat(" ", maxInventoryBytes+1))); err == nil {
		t.Fatal("oversized inventory accepted")
	}
	item := `{"version":"8.4.27","role":"web"}`
	if _, err := readInventory(strings.NewReader("[" + strings.TrimSuffix(strings.Repeat(item+",", maxInventoryRecords+1), ",") + "]")); err == nil {
		t.Fatal("too many inventory entries accepted")
	}
}
