package scan

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func adviceFixture(t *testing.T) (*FileAdviceRecorder, VerifiedCaller, Request, Result) {
	t.Helper()
	r, err := OpenFileAdviceRecorder(filepath.Join(t.TempDir(), "private-advice"))
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("synthetic private attachment")
	req := coordinatorRequest(payload)
	result := coordinatorResult(req, Clean)
	caller := VerifiedCaller{OwnerProduct: req.OwnerProduct, Subject: "service:scanner"}
	return r, caller, req, result
}

func TestPrivateAdviceReceiptDurabilityAndMinimization(t *testing.T) {
	recorder, caller, req, result := adviceFixture(t)
	lease := "lease:private-workspace-49"
	if err := recorder.RecordAdvice(context.Background(), caller, lease, req, result, EligibleForOwnerReview); err != nil {
		t.Fatal(err)
	}
	receipt, err := recorder.ReadReceipt(context.Background(), caller, lease)
	if err != nil {
		t.Fatalf("persisted advice not recoverable: %v", err)
	}
	if receipt.Verdict != Clean || receipt.Recommendation != EligibleForOwnerReview || receipt.Engine != "clamav" ||
		receipt.LeaseFingerprint != adviceLeaseFingerprint(caller.OwnerProduct, lease) {
		t.Fatalf("incorrect private audit receipt: %+v", receipt)
	}
	entries, err := os.ReadDir(recorder.dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("wrong audit count: %d %v", len(entries), err)
	}
	info, err := entries[0].Info()
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("receipt not private 0600: %v %v", info, err)
	}
	content, err := os.ReadFile(filepath.Join(recorder.dir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{req.ObjectID, req.RequestID, req.SHA256, lease, caller.Subject, "synthetic private attachment"} {
		if strings.Contains(string(content), s) || strings.Contains(entries[0].Name(), s) {
			t.Fatalf("sensitive metadata present in receipt filename/content")
		}
	}
	reopened, err := OpenFileAdviceRecorder(recorder.dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.ReadReceipt(context.Background(), caller, lease); err != nil {
		t.Fatalf("restart lost private receipt: %v", err)
	}
	if err := reopened.RecordAdvice(context.Background(), caller, lease, req, result, EligibleForOwnerReview); !errors.Is(err, ErrAdviceAlreadyRecorded) {
		t.Fatalf("duplicate immutable advice was accepted: %v", err)
	}
	other := caller
	other.OwnerProduct = "another-product"
	if _, err := reopened.ReadReceipt(context.Background(), other, lease); err == nil {
		t.Fatal("cross-product audit read accepted")
	}
}

func TestPrivateAdviceReceiptRejectsUnsafeBindings(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*VerifiedCaller, *string, *Request, *Result, *Disposition)
	}{
		{"invalid_lease", func(_ *VerifiedCaller, l *string, _ *Request, _ *Result, _ *Disposition) { *l = "../private" }},
		{"wrong_caller", func(c *VerifiedCaller, _ *string, _ *Request, _ *Result, _ *Disposition) {
			c.OwnerProduct = "unrelated"
		}},
		{"missing_subject", func(c *VerifiedCaller, _ *string, _ *Request, _ *Result, _ *Disposition) { c.Subject = "" }},
		{"wrong_object", func(_ *VerifiedCaller, _ *string, _ *Request, r *Result, _ *Disposition) { r.ObjectID = "file:wrong" }},
		{"wrong_sha256", func(_ *VerifiedCaller, _ *string, _ *Request, r *Result, _ *Disposition) {
			r.SHA256 = strings.Repeat("0", 64)
		}},
		{"bad_result", func(_ *VerifiedCaller, _ *string, _ *Request, r *Result, _ *Disposition) { r.Verdict = "unknown" }},
		{"invalid_request", func(_ *VerifiedCaller, _ *string, req *Request, _ *Result, _ *Disposition) { req.ObjectID = "../path" }},
		{"wrong_recommendation", func(_ *VerifiedCaller, _ *string, _ *Request, _ *Result, rec *Disposition) {
			*rec = RetainPendingReview
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, c, req, result := adviceFixture(t)
			lease := "pending:one"
			rec := EligibleForOwnerReview
			tc.mutate(&c, &lease, &req, &result, &rec)
			if err := f.RecordAdvice(context.Background(), c, lease, req, result, rec); err == nil {
				t.Fatal("invalid advice accepted")
			}
			entries, err := os.ReadDir(f.dir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("invalid advice wrote receipt: %v %v", entries, err)
			}
		})
	}
}

func TestAdviceReceiptIncompleteMarkerAndTamperingFailClosed(t *testing.T) {
	f, c, req, result := adviceFixture(t)
	lease := "pending:crash"
	path := filepath.Join(f.dir, adviceLeaseFingerprint(c.OwnerProduct, lease)+".advice")
	// Simulated crash after O_EXCL marker creation.
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.RecordAdvice(context.Background(), c, lease, req, result, EligibleForOwnerReview); !errors.Is(err, ErrAdviceAlreadyRecorded) {
		t.Fatalf("crashed marker overwritten: %v", err)
	}
	if _, err := f.ReadReceipt(context.Background(), c, lease); err == nil {
		t.Fatal("incomplete marker accepted as advice")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := f.RecordAdvice(context.Background(), c, lease, req, result, EligibleForOwnerReview); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, []byte("unexpected")...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.ReadReceipt(context.Background(), c, lease); err == nil {
		t.Fatal("trailing content accepted")
	}
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := f.ReadReceipt(context.Background(), c, lease); err == nil {
		t.Fatal("world-readable audit accepted")
	}
}

func TestAdviceRecorderRejectsUnsafeDirectoryAndCancellation(t *testing.T) {
	parent := t.TempDir()
	bad := filepath.Join(parent, "public")
	if err := os.Mkdir(bad, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileAdviceRecorder(bad); err == nil {
		t.Fatal("public audit dir accepted")
	}
	alias := filepath.Join(parent, "symlink")
	if err := os.Symlink(bad, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileAdviceRecorder(alias); err == nil {
		t.Fatal("symlinked audit dir accepted")
	}
	f, c, req, result := adviceFixture(t)
	if err := os.Chmod(f.dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := f.RecordAdvice(context.Background(), c, "lease:drift", req, result, EligibleForOwnerReview); err == nil {
		t.Fatal("unsafe audit permissions accepted")
	}
	if err := os.Chmod(f.dir, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.RecordAdvice(ctx, c, "lease:cancel", req, result, EligibleForOwnerReview); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled audit write accepted: %v", err)
	}
}

func TestAdviceRecorderConcurrentDuplicateAtomicity(t *testing.T) {
	f, c, req, result := adviceFixture(t)
	var accepted, duplicate, other atomic.Int64
	const attempts = 40
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := f.RecordAdvice(context.Background(), c, "lease:shared", req, result, EligibleForOwnerReview)
			switch {
			case err == nil:
				accepted.Add(1)
			case errors.Is(err, ErrAdviceAlreadyRecorded):
				duplicate.Add(1)
			default:
				other.Add(1)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 || duplicate.Load() != attempts-1 || other.Load() != 0 {
		t.Fatalf("non-atomic audit admission: accepted=%d duplicate=%d other=%d", accepted.Load(), duplicate.Load(), other.Load())
	}
	if _, err := f.ReadReceipt(context.Background(), c, "lease:shared"); err != nil {
		t.Fatalf("winning record not durable: %v", err)
	}
}

func TestCoordinatorRecordsPrivateAuditableAdviceWithoutRelease(t *testing.T) {
	content := []byte("unpublished owner-held synthetic content")
	req := coordinatorRequest(content)
	receipt, err := OpenFileAdviceRecorder(filepath.Join(t.TempDir(), "private-receipts"))
	if err != nil {
		t.Fatal(err)
	}
	admission, err := OpenFileAdmission(filepath.Join(t.TempDir(), "private-leases"))
	if err != nil {
		t.Fatal(err)
	}
	var engineCalls, sourceCloses atomic.Int64
	worker := ScanCoordinator{
		Auth: coordinatorAuth(), Capacity: testScanLimiter(), Readiness: syntheticReadiness(), Admission: admission, Record: receipt,
		Source: sourceOwnerFunc(func(_ context.Context, _ VerifiedCaller, actual Request) (HeldObject, error) {
			if actual != req {
				t.Fatal("unexpected owner object")
			}
			return coordinatorHeld(req, countedClose{ReadCloser: io.NopCloser(bytes.NewReader(content)), onClose: func() { sourceCloses.Add(1) }}), nil
		}),
		Engine: malwareEngineFunc(func(_ context.Context, actual Request, src io.ReadCloser) (Result, error) {
			engineCalls.Add(1)
			data, err := io.ReadAll(src)
			if err != nil || !bytes.Equal(data, content) {
				t.Fatal("invalid held source data")
			}
			return coordinatorResult(actual, Malicious), nil
		}),
	}
	advice, err := worker.Process(context.Background(), []byte("authorized-fixture"), req)
	if err != nil {
		t.Fatalf("coordinator failed: %v", err)
	}
	if advice.Recommendation != RetainPendingReview || engineCalls.Load() != 1 || sourceCloses.Load() != 1 {
		t.Fatalf("unsafe advice or leaked held source: %+v", advice)
	}
	c := VerifiedCaller{OwnerProduct: req.OwnerProduct, Subject: "service:test"}
	saved, err := receipt.ReadReceipt(context.Background(), c, advice.LeaseID)
	if err != nil || saved.Verdict != Malicious || saved.Recommendation != RetainPendingReview {
		t.Fatalf("malicious advice receipt absent or unsafe: %+v %v", saved, err)
	}
	_, err = worker.Process(context.Background(), []byte("authorized-fixture"), req)
	if !errors.Is(err, ErrAdmissionReplay) || engineCalls.Load() != 1 {
		t.Fatalf("duplicate executed despite owner lease hold: %v", err)
	}
}
