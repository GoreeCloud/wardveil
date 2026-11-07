package scan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

type authenticatorFunc func(context.Context, []byte) (VerifiedCaller, error)

func (f authenticatorFunc) Authenticate(ctx context.Context, credential []byte) (VerifiedCaller, error) {
	return f(ctx, credential)
}

type sourceOwnerFunc func(context.Context, VerifiedCaller, Request) (HeldObject, error)

func (f sourceOwnerFunc) OpenHeld(ctx context.Context, caller VerifiedCaller, req Request) (HeldObject, error) {
	return f(ctx, caller, req)
}

type malwareEngineFunc func(context.Context, Request, io.ReadCloser) (Result, error)

func (f malwareEngineFunc) Scan(ctx context.Context, req Request, content io.ReadCloser) (Result, error) {
	return f(ctx, req, content)
}

type recordFunc func(context.Context, VerifiedCaller, string, Request, Result, Disposition) error

func (f recordFunc) RecordAdvice(ctx context.Context, caller VerifiedCaller, lease string, req Request, result Result, d Disposition) error {
	return f(ctx, caller, lease, req, result, d)
}

type trackedContent struct {
	io.Reader
	closes int
}

func (c *trackedContent) Close() error { c.closes++; return nil }

func coordinatorRequest(payload []byte) Request {
	sum := sha256.Sum256(payload)
	return Request{
		SchemaVersion: SchemaVersion,
		RequestID:     "req:coordinator-1",
		OwnerProduct:  "workspace",
		ObjectID:      "file:234",
		SHA256:        hex.EncodeToString(sum[:]),
		SizeBytes:     int64(len(payload)),
		RequestedAt:   time.Now().UTC(),
	}
}
func coordinatorResult(req Request, verdict Verdict) Result {
	return Result{
		SchemaVersion: SchemaVersion,
		RequestID:     req.RequestID,
		OwnerProduct:  req.OwnerProduct,
		ObjectID:      req.ObjectID,
		SHA256:        req.SHA256,
		Verdict:       verdict,
		Engine:        "clamav",
		EngineVersion: "1.4.6",
		ScannedAt:     time.Now().UTC(),
	}
}
func coordinatorHeld(req Request, content io.ReadCloser) HeldObject {
	return HeldObject{
		OwnerProduct: req.OwnerProduct,
		ObjectID:     req.ObjectID,
		SHA256:       req.SHA256,
		SizeBytes:    req.SizeBytes,
		LeaseID:      "pending:lease-19",
		Pending:      true,
		Content:      content,
	}
}
func coordinatorAuth() CallerAuthenticator {
	return authenticatorFunc(func(_ context.Context, cred []byte) (VerifiedCaller, error) {
		if !bytes.Equal(cred, []byte("authorized-fixture")) {
			return VerifiedCaller{}, errors.New("fake auth rejection")
		}
		return VerifiedCaller{OwnerProduct: "workspace", Subject: "test:service"}, nil
	})
}

func TestCoordinatorCleanAndMaliciousRemainAdvisory(t *testing.T) {
	payload := []byte("verified bytes remain owner-held")
	req := coordinatorRequest(payload)
	for _, tc := range []struct {
		verdict Verdict
		want    Disposition
	}{
		{Clean, EligibleForOwnerReview},
		{Malicious, RetainPendingReview},
	} {
		t.Run(string(tc.verdict), func(t *testing.T) {
			reader := &trackedContent{Reader: bytes.NewReader(payload)}
			openCalls, scanCalls, recordCalls := 0, 0, 0
			worker := ScanCoordinator{
				Auth: coordinatorAuth(),
				Source: sourceOwnerFunc(func(_ context.Context, caller VerifiedCaller, actual Request) (HeldObject, error) {
					openCalls++
					if caller.OwnerProduct != req.OwnerProduct || actual != req {
						t.Fatal("incorrect source authorization scope")
					}
					return coordinatorHeld(req, reader), nil
				}),
				Engine: malwareEngineFunc(func(_ context.Context, actual Request, source io.ReadCloser) (Result, error) {
					scanCalls++
					buf, err := io.ReadAll(source)
					if err != nil || !bytes.Equal(buf, payload) {
						t.Fatalf("wrong bytes: %q %v", buf, err)
					}
					if err := source.Close(); err != nil {
						t.Fatal(err)
					}
					return coordinatorResult(actual, tc.verdict), nil
				}),
				Record: recordFunc(func(_ context.Context, caller VerifiedCaller, lease string, actual Request, result Result, rec Disposition) error {
					recordCalls++
					if caller.OwnerProduct != req.OwnerProduct || lease != "pending:lease-19" || actual != req ||
						result.Verdict != tc.verdict || rec != tc.want {
						t.Fatal("incorrect recorded advice binding")
					}
					return nil
				}),
			}
			advice, err := worker.Process(context.Background(), []byte("authorized-fixture"), req)
			if err != nil {
				t.Fatal(err)
			}
			if advice.Recommendation != tc.want || advice.Result.Verdict != tc.verdict ||
				advice.LeaseID != "pending:lease-19" || openCalls != 1 || scanCalls != 1 || recordCalls != 1 || reader.closes != 1 {
				t.Fatalf("unexpected workflow: %+v opens=%d scans=%d records=%d closes=%d",
					advice, openCalls, scanCalls, recordCalls, reader.closes)
			}
		})
	}
}

func TestCoordinatorRejectsUntrustedCallerBeforeSource(t *testing.T) {
	payload := []byte("safe")
	req := coordinatorRequest(payload)
	for _, tc := range []struct {
		name       string
		credential []byte
		mutate     func(*Request)
		auth       CallerAuthenticator
	}{
		{"missing_credentials", nil, nil, coordinatorAuth()},
		{"unknown_credentials", []byte("wrong"), nil, coordinatorAuth()},
		{"oversized_credentials", bytes.Repeat([]byte("x"), maxCredentialBytes+1), nil, coordinatorAuth()},
		{"request_invalid", []byte("authorized-fixture"), func(r *Request) { r.ObjectID = "../file" }, coordinatorAuth()},
		{"cross_product_identity", []byte("authorized-fixture"), nil, authenticatorFunc(func(context.Context, []byte) (VerifiedCaller, error) {
			return VerifiedCaller{OwnerProduct: "unrelated", Subject: "test:user"}, nil
		})},
		{"missing_subject", []byte("authorized-fixture"), nil, authenticatorFunc(func(context.Context, []byte) (VerifiedCaller, error) {
			return VerifiedCaller{OwnerProduct: "workspace"}, nil
		})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			actual := req
			if tc.mutate != nil {
				tc.mutate(&actual)
			}
			opens, scans, records := 0, 0, 0
			w := ScanCoordinator{
				Auth: tc.auth,
				Source: sourceOwnerFunc(func(context.Context, VerifiedCaller, Request) (HeldObject, error) {
					opens++
					return coordinatorHeld(req, io.NopCloser(bytes.NewReader(payload))), nil
				}),
				Engine: malwareEngineFunc(func(context.Context, Request, io.ReadCloser) (Result, error) {
					scans++
					return coordinatorResult(req, Clean), nil
				}),
				Record: recordFunc(func(context.Context, VerifiedCaller, string, Request, Result, Disposition) error {
					records++
					return nil
				}),
			}
			out, err := w.Process(context.Background(), tc.credential, actual)
			if err == nil || out != (ScanAdvice{}) || opens != 0 || scans != 0 || records != 0 {
				t.Fatalf("unauthorized or invalid input passed: %+v %v, opens=%d", out, err, opens)
			}
		})
	}
}

func TestCoordinatorHeldAttestationFailClosed(t *testing.T) {
	payload := []byte("fixture")
	req := coordinatorRequest(payload)
	for _, tc := range []struct {
		name   string
		mutate func(*HeldObject)
	}{
		{"hold_not_pending", func(h *HeldObject) { h.Pending = false }},
		{"wrong_owner", func(h *HeldObject) { h.OwnerProduct = "unrelated" }},
		{"wrong_object", func(h *HeldObject) { h.ObjectID = "file:different" }},
		{"wrong_hash", func(h *HeldObject) { h.SHA256 = strings.Repeat("a", 64) }},
		{"wrong_size", func(h *HeldObject) { h.SizeBytes++ }},
		{"invalid_lease", func(h *HeldObject) { h.LeaseID = "../forged" }},
		{"empty_lease", func(h *HeldObject) { h.LeaseID = "" }},
		{"missing_content", func(h *HeldObject) { h.Content = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader := &trackedContent{Reader: bytes.NewReader(payload)}
			engineCalls, recordCalls := 0, 0
			held := coordinatorHeld(req, reader)
			tc.mutate(&held)
			w := ScanCoordinator{
				Auth:   coordinatorAuth(),
				Source: sourceOwnerFunc(func(context.Context, VerifiedCaller, Request) (HeldObject, error) { return held, nil }),
				Engine: malwareEngineFunc(func(context.Context, Request, io.ReadCloser) (Result, error) {
					engineCalls++
					return coordinatorResult(req, Clean), nil
				}),
				Record: recordFunc(func(context.Context, VerifiedCaller, string, Request, Result, Disposition) error {
					recordCalls++
					return nil
				}),
			}
			out, err := w.Process(context.Background(), []byte("authorized-fixture"), req)
			wantClose := 1
			if held.Content == nil {
				wantClose = 0
			}
			if err == nil || out != (ScanAdvice{}) || engineCalls != 0 || recordCalls != 0 || reader.closes != wantClose {
				t.Fatalf("unsafe hold accepted: %+v err=%v calls=%d/%d close=%d", out, err, engineCalls, recordCalls, reader.closes)
			}
		})
	}
}

func TestCoordinatorCannotTrustForgedOrIncompleteScan(t *testing.T) {
	payload := []byte("verified-read-content")
	req := coordinatorRequest(payload)
	cases := []struct {
		name    string
		file    []byte
		mode    string
		verdict func(*Result)
	}{
		{"scanner_error", payload, "error", nil},
		{"scanner_skipped_read", payload, "skip", nil},
		{"scanner_partial_read", payload, "partial", nil},
		{"source_shorter_than_metadata", payload[:6], "full", nil},
		{"source_longer_than_metadata", append(bytes.Clone(payload), 'x'), "full", nil},
		{"source_digest_mismatch", bytes.Repeat([]byte("x"), len(payload)), "full", nil},
		{"forged_result_request", payload, "full", func(r *Result) { r.RequestID = "not-original" }},
		{"forged_result_object", payload, "full", func(r *Result) { r.ObjectID = "file:other" }},
		{"forged_result_digest", payload, "full", func(r *Result) { r.SHA256 = strings.Repeat("b", 64) }},
		{"invalid_result_verdict", payload, "full", func(r *Result) { r.Verdict = "untrusted" }},
		{"invalid_result_engine", payload, "full", func(r *Result) { r.Engine = "bad/name" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reader := &trackedContent{Reader: bytes.NewReader(tc.file)}
			engineCalls, recordCalls := 0, 0
			w := ScanCoordinator{
				Auth: coordinatorAuth(),
				Source: sourceOwnerFunc(func(context.Context, VerifiedCaller, Request) (HeldObject, error) {
					return coordinatorHeld(req, reader), nil
				}),
				Engine: malwareEngineFunc(func(_ context.Context, actual Request, source io.ReadCloser) (Result, error) {
					engineCalls++
					switch tc.mode {
					case "error":
						return Result{}, errors.New("scanner offline")
					case "skip":
					case "partial":
						var b [3]byte
						_, _ = source.Read(b[:])
					default:
						if _, err := io.Copy(io.Discard, source); err != nil {
							t.Fatal(err)
						}
					}
					result := coordinatorResult(actual, Clean)
					if tc.verdict != nil {
						tc.verdict(&result)
					}
					return result, nil
				}),
				Record: recordFunc(func(context.Context, VerifiedCaller, string, Request, Result, Disposition) error {
					recordCalls++
					return nil
				}),
			}
			out, err := w.Process(context.Background(), []byte("authorized-fixture"), req)
			if err == nil || out != (ScanAdvice{}) || engineCalls != 1 || recordCalls != 0 || reader.closes != 1 {
				t.Fatalf("failure did not preserve hold: %+v err=%v calls=%d/%d closes=%d", out, err, engineCalls, recordCalls, reader.closes)
			}
		})
	}
}

func TestCoordinatorRecorderOrSourceFailureLeavesHold(t *testing.T) {
	payload := []byte("hello")
	req := coordinatorRequest(payload)
	for _, sourceFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "record_unavailable", true: "owner_unavailable"}[sourceFails], func(t *testing.T) {
			reader := &trackedContent{Reader: bytes.NewReader(payload)}
			scans, records := 0, 0
			w := ScanCoordinator{
				Auth: coordinatorAuth(),
				Source: sourceOwnerFunc(func(context.Context, VerifiedCaller, Request) (HeldObject, error) {
					if sourceFails {
						return HeldObject{}, errors.New("owner private error")
					}
					return coordinatorHeld(req, reader), nil
				}),
				Engine: malwareEngineFunc(func(_ context.Context, actual Request, r io.ReadCloser) (Result, error) {
					scans++
					_, _ = io.Copy(io.Discard, r)
					return coordinatorResult(actual, Clean), nil
				}),
				Record: recordFunc(func(context.Context, VerifiedCaller, string, Request, Result, Disposition) error {
					records++
					return errors.New("temporary audit backend unavailable")
				}),
			}
			out, err := w.Process(context.Background(), []byte("authorized-fixture"), req)
			if err == nil || out != (ScanAdvice{}) || strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "temporary audit backend") {
				t.Fatalf("internal error leaked or returned advice: %+v %v", out, err)
			}
			if sourceFails && (scans != 0 || records != 0 || reader.closes != 0) {
				t.Fatal("source failure did not stop downstream")
			}
			if !sourceFails && (scans != 1 || records != 1 || reader.closes != 1) {
				t.Fatal("record failure did not close content")
			}
		})
	}
}

func TestCoordinatorCanceledContextNeverRecordsAdvice(t *testing.T) {
	payload := []byte("verified")
	req := coordinatorRequest(payload)
	reader := &trackedContent{Reader: bytes.NewReader(payload)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	w := ScanCoordinator{
		Auth: coordinatorAuth(),
		Source: sourceOwnerFunc(func(context.Context, VerifiedCaller, Request) (HeldObject, error) {
			return coordinatorHeld(req, reader), nil
		}),
		Engine: malwareEngineFunc(func(_ context.Context, r Request, c io.ReadCloser) (Result, error) {
			_, _ = io.Copy(io.Discard, c)
			cancel()
			return coordinatorResult(r, Clean), nil
		}),
		Record: recordFunc(func(context.Context, VerifiedCaller, string, Request, Result, Disposition) error { calls++; return nil }),
	}
	out, err := w.Process(ctx, []byte("authorized-fixture"), req)
	if err == nil || out != (ScanAdvice{}) || calls != 0 || reader.closes != 1 {
		t.Fatal("canceled scan returned release-eligible advice")
	}
}

func TestCoordinatorRejectsMissingDependenciesOrContext(t *testing.T) {
	req := coordinatorRequest([]byte("some data"))
	for _, tc := range []struct {
		name   string
		worker ScanCoordinator
		ctx    context.Context
	}{
		{"unconfigured", ScanCoordinator{}, context.Background()},
		{"nil_context", ScanCoordinator{}, nil},
		{"canceled_context", ScanCoordinator{
			Auth: coordinatorAuth(),
			Source: sourceOwnerFunc(func(context.Context, VerifiedCaller, Request) (HeldObject, error) {
				t.Fatal("opened canceled context")
				return HeldObject{}, nil
			}),
			Engine: malwareEngineFunc(func(context.Context, Request, io.ReadCloser) (Result, error) {
				t.Fatal("scanned canceled context")
				return Result{}, nil
			}),
			Record: recordFunc(func(context.Context, VerifiedCaller, string, Request, Result, Disposition) error {
				t.Fatal("recorded canceled context")
				return nil
			}),
		}, func() context.Context { ctx, cancel := context.WithCancel(context.Background()); cancel(); return ctx }()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			advice, err := tc.worker.Process(tc.ctx, []byte("authorized-fixture"), req)
			if err == nil || advice != (ScanAdvice{}) {
				t.Fatalf("unexpected accepted invalid coordinator: %+v", advice)
			}
		})
	}
}

func TestCoordinatorClosesSourceEvenWhenOwnerAlsoReportsError(t *testing.T) {
	req := coordinatorRequest([]byte("fixture"))
	reader := &trackedContent{Reader: bytes.NewReader([]byte("fixture"))}
	w := ScanCoordinator{
		Auth: coordinatorAuth(),
		Source: sourceOwnerFunc(func(context.Context, VerifiedCaller, Request) (HeldObject, error) {
			return coordinatorHeld(req, reader), errors.New("owner rejected after opening")
		}),
		Engine: malwareEngineFunc(func(context.Context, Request, io.ReadCloser) (Result, error) {
			t.Fatal("scanner must not run after owner error")
			return Result{}, nil
		}),
		Record: recordFunc(func(context.Context, VerifiedCaller, string, Request, Result, Disposition) error {
			t.Fatal("result must not record after owner error")
			return nil
		}),
	}
	out, err := w.Process(context.Background(), []byte("authorized-fixture"), req)
	if err == nil || out != (ScanAdvice{}) || reader.closes != 1 {
		t.Fatalf("source leak on error: %+v err=%v closed=%d", out, err, reader.closes)
	}
}
