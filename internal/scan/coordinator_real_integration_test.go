package scan

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestCoordinatorLiveClamd is a synthetic local integration only. It
// exercises the entire in-process handshake against a real isolated daemon,
// while intentionally using fake authentication and owner-held content.
// There is no external authenticated service or real source product here.
func TestCoordinatorLiveClamd(t *testing.T) {
	socket := os.Getenv("WARDVEIL_CLAMD_TEST_SOCKET")
	if socket == "" {
		t.Skip("requires explicitly isolated nonproduction ClamAV Unix socket")
	}
	for _, tc := range []struct {
		name    string
		payload string
		want    Verdict
		dispose Disposition
	}{
		{"clean", "wardveil integration test ordinary benign content\n", Clean, EligibleForOwnerReview},
		{"synthetic_detection", "wardveil-integration-test-detection-fixture-2026\n", Malicious, RetainPendingReview},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := []byte(tc.payload)
			req := coordinatorRequest(payload)
			reader := &trackedContent{Reader: bytes.NewReader(payload)}
			receipt, err := OpenFileAdviceRecorder(filepath.Join(t.TempDir(), "private-advice"))
			if err != nil {
				t.Fatal(err)
			}
			admission, err := OpenFileAdmission(filepath.Join(t.TempDir(), "private-journal"))
			if err != nil {
				t.Fatal(err)
			}
			w := ScanCoordinator{
				Readiness: syntheticReadiness(),
				Admission: admission,
				Capacity:  testScanLimiter(),
				Auth:      coordinatorAuth(),
				Source: sourceOwnerFunc(func(_ context.Context, caller VerifiedCaller, actual Request) (HeldObject, error) {
					if caller.OwnerProduct != req.OwnerProduct || actual != req {
						t.Fatal("owner/caller mismatch")
					}
					return coordinatorHeld(req, reader), nil
				}),
				Engine: Clamd{SocketPath: socket, MaxBytes: 1024, Timeout: 5 * time.Second},
				Record: receipt,
			}
			out, err := w.Process(context.Background(), []byte("authorized-fixture"), req)
			if err != nil {
				t.Fatal(err)
			}
			if out.Result.Verdict != tc.want || out.Recommendation != tc.dispose ||
				out.Result.Engine != "clamav" || out.Result.EngineVersion == "" ||
				reader.closes != 1 {
				t.Fatalf("incorrect real-engine handshake: %+v closes=%d", out, reader.closes)
			}
			saved, err := receipt.ReadReceipt(context.Background(),
				VerifiedCaller{OwnerProduct: req.OwnerProduct, Subject: "test:service"}, out.LeaseID)
			if err != nil || saved.Verdict != tc.want || saved.Recommendation != tc.dispose ||
				saved.Engine != "clamav" || saved.LeaseFingerprint == "" {
				t.Fatalf("missing or inconsistent private advisory receipt: %+v %v", saved, err)
			}
			if tc.want == Malicious && out.Result.SignatureID != "Wardveil.Test.Fixture.UNOFFICIAL" {
				t.Fatalf("incorrect synthetic signature: %q", out.Result.SignatureID)
			}
			t.Logf("real engine=%s verdict=%s owner advice=%s", out.Result.EngineVersion, out.Result.Verdict, out.Recommendation)
		})
	}
}

// Require no worker escape hatch that provides raw file paths or URLs;
// the only content entering an engine is the trusted owner's reader.
var _ io.ReadCloser = (*trackedContent)(nil)
