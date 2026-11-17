package scan

import (
	"strings"
	"testing"
	"time"
)

func exampleRequest(now time.Time) Request {
	return Request{
		SchemaVersion: SchemaVersion, RequestID: "scan-0001", OwnerProduct: "notebook",
		ObjectID: "upload:42", SHA256: strings.Repeat("a", 64), SizeBytes: 0,
		RequestedAt: now.Add(-time.Minute),
	}
}

func exampleResult(request Request, now time.Time) Result {
	return Result{
		SchemaVersion: SchemaVersion, RequestID: request.RequestID,
		OwnerProduct: request.OwnerProduct, ObjectID: request.ObjectID,
		SHA256: request.SHA256, Verdict: Clean, Engine: "clamav",
		EngineVersion: "1.0.0", ScannedAt: now,
	}
}

func TestRequestContract(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	base := exampleRequest(now)
	if err := base.Validate(now); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		change func(*Request)
	}{
		{"unknown_schema", func(r *Request) { r.SchemaVersion = "2" }},
		{"path_traversal", func(r *Request) { r.ObjectID = "../private" }},
		{"oversized_identifier", func(r *Request) { r.OwnerProduct = strings.Repeat("x", 97) }},
		{"uppercase_digest", func(r *Request) { r.SHA256 = strings.Repeat("A", 64) }},
		{"malformed_digest", func(r *Request) { r.SHA256 = strings.Repeat("z", 64) }},
		{"negative_size", func(r *Request) { r.SizeBytes = -1 }},
		{"oversized_metadata", func(r *Request) { r.SizeBytes = 1<<40 + 1 }},
		{"stale_request", func(r *Request) { r.RequestedAt = now.Add(-25 * time.Hour) }},
		{"future_request", func(r *Request) { r.RequestedAt = now.Add(10 * time.Minute) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := base
			tc.change(&r)
			if err := r.Validate(now); err == nil {
				t.Fatal("expected invalid request")
			}
		})
	}
}

func TestResultBindingAndAdvisoryDisposition(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	request := exampleRequest(now)
	clean := exampleResult(request, now)
	if err := clean.ValidateFor(request, now); err != nil {
		t.Fatal(err)
	}
	if Recommend(clean.Verdict) != EligibleForOwnerReview {
		t.Fatal("clean result recommendation missing")
	}

	for _, verdict := range []Verdict{Malicious, Suspicious, Inconclusive, ScanError, "unrecognized", ""} {
		if Recommend(verdict) != RetainPendingReview {
			t.Fatalf("unsafe release recommendation for %q", verdict)
		}
	}

	mismatch := clean
	mismatch.ObjectID = "upload:other"
	if err := mismatch.ValidateFor(request, now); err == nil {
		t.Fatal("cross-object result accepted")
	}
	mismatch = clean
	mismatch.OwnerProduct = "other"
	if err := mismatch.ValidateFor(request, now); err == nil {
		t.Fatal("cross-product result accepted")
	}
	mismatch = clean
	mismatch.SHA256 = strings.Repeat("b", 64)
	if err := mismatch.ValidateFor(request, now); err == nil {
		t.Fatal("wrong hash result accepted")
	}
	mismatch = clean
	mismatch.RequestID = "scan-0002"
	if err := mismatch.ValidateFor(request, now); err == nil {
		t.Fatal("wrong request result accepted")
	}
	mismatch = clean
	mismatch.Verdict = "unknown"
	if err := mismatch.ValidateFor(request, now); err == nil {
		t.Fatal("unknown verdict accepted")
	}
	mismatch = clean
	mismatch.Engine = "../../../etc"
	if err := mismatch.ValidateFor(request, now); err == nil {
		t.Fatal("invalid engine accepted")
	}
	mismatch = clean
	mismatch.ScannedAt = now.Add(20 * time.Minute)
	if err := mismatch.ValidateFor(request, now); err == nil {
		t.Fatal("future scan accepted")
	}
}

func TestResultRequiresValidatedOriginalRequest(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cases := []struct {
		name   string
		change func(*Request)
	}{
		{"invalid_owner", func(r *Request) { r.OwnerProduct = "../private" }},
		{"invalid_object", func(r *Request) { r.ObjectID = "../private" }},
		{"bad_digest", func(r *Request) { r.SHA256 = strings.Repeat("Z", 64) }},
		{"oversized_metadata", func(r *Request) { r.SizeBytes = 1<<40 + 1 }},
		{"expired_intake", func(r *Request) { r.RequestedAt = now.Add(-25 * time.Hour) }},
		{"unsupported_schema", func(r *Request) { r.SchemaVersion = "99" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			original := exampleRequest(now)
			tc.change(&original)
			matching := exampleResult(original, now)
			// Result binding alone must not rehabilitate an invalid request.
			if err := matching.ValidateFor(original, now); err == nil {
				t.Fatal("accepted result matching an invalid original request")
			}
		})
	}
}

func TestValidatedRecommendationRetainsHoldForUntrustedCleanVerdicts(t *testing.T) {
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	request := exampleRequest(now)
	clean := exampleResult(request, now)
	if RecommendFor(request, clean, now) != EligibleForOwnerReview {
		t.Fatal("a valid matching clean result should remain eligible for owner review only")
	}
	mutatedResults := []struct {
		name   string
		change func(*Result)
	}{
		{"wrong_request", func(r *Result) { r.RequestID = "other" }},
		{"wrong_owner", func(r *Result) { r.OwnerProduct = "other" }},
		{"wrong_object", func(r *Result) { r.ObjectID = "other" }},
		{"wrong_digest", func(r *Result) { r.SHA256 = strings.Repeat("b", 64) }},
		{"wrong_schema", func(r *Result) { r.SchemaVersion = "99" }},
		{"unknown_engine", func(r *Result) { r.Engine = "../invalid" }},
		{"future_timestamp", func(r *Result) { r.ScannedAt = now.Add(10 * time.Minute) }},
		{"before_intake", func(r *Result) { r.ScannedAt = now.Add(-time.Hour) }},
		{"unknown_verdict", func(r *Result) { r.Verdict = Verdict("invalid") }},
	}
	for _, tc := range mutatedResults {
		t.Run(tc.name, func(t *testing.T) {
			bad := clean
			tc.change(&bad)
			if got := RecommendFor(request, bad, now); got != RetainPendingReview {
				t.Fatalf("unvalidated clean scan result received %q", got)
			}
		})
	}
	mutatedRequests := []struct {
		name   string
		change func(*Request)
	}{
		{"expired_request", func(r *Request) { r.RequestedAt = now.Add(-25 * time.Hour) }},
		{"invalid_owner", func(r *Request) { r.OwnerProduct = "../private" }},
		{"invalid_digest", func(r *Request) { r.SHA256 = strings.Repeat("Z", 64) }},
		{"invalid_size", func(r *Request) { r.SizeBytes = -1 }},
		{"invalid_schema", func(r *Request) { r.SchemaVersion = "2" }},
	}
	for _, tc := range mutatedRequests {
		t.Run(tc.name, func(t *testing.T) {
			bad := request
			tc.change(&bad)
			matched := exampleResult(bad, now)
			if got := RecommendFor(bad, matched, now); got != RetainPendingReview {
				t.Fatalf("invalid intake with matching clean result received %q", got)
			}
		})
	}
	for _, verdict := range []Verdict{Malicious, Suspicious, Inconclusive, ScanError} {
		outcome := clean
		outcome.Verdict = verdict
		if got := RecommendFor(request, outcome, now); got != RetainPendingReview {
			t.Fatalf("non-clean verdict %q received %q", verdict, got)
		}
	}
}

func TestRecommendationRequiresRecentRequestAtAdvisoryTime(t *testing.T) {
	initial := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	request := exampleRequest(initial)
	result := exampleResult(request, initial)
	if got := RecommendFor(request, result, initial.Add(25*time.Hour)); got != RetainPendingReview {
		t.Fatalf("stale queued result must retain owner hold, got %q", got)
	}
}
