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
