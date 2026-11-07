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
			records := 0
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
				Record: recordFunc(func(_ context.Context, caller VerifiedCaller, lease string, actual Request, result Result, rec Disposition) error {
					records++
					if actual != req || lease != "pending:lease-19" || caller.OwnerProduct != req.OwnerProduct ||
						result.Verdict != tc.want || rec != tc.dispose {
						t.Fatal("recorded unsafe or mismatched advice")
					}
					return nil
				}),
			}
			out, err := w.Process(context.Background(), []byte("authorized-fixture"), req)
			if err != nil {
				t.Fatal(err)
			}
			if out.Result.Verdict != tc.want || out.Recommendation != tc.dispose ||
				out.Result.Engine != "clamav" || out.Result.EngineVersion == "" ||
				records != 1 || reader.closes != 1 {
				t.Fatalf("incorrect real-engine handshake: %+v records=%d closes=%d", out, records, reader.closes)
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
