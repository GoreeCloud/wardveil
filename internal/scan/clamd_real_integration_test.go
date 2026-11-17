package scan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// TestClamdLiveEngine is opt-in: it requires a separately started, isolated
// real clamd with a test-only .hdb rule. Default CI does not start a daemon.
// Never point this at a production clamd or submit private user files.
func TestClamdLiveEngine(t *testing.T) {
	socket := os.Getenv("WARDVEIL_CLAMD_TEST_SOCKET")
	if socket == "" {
		t.Skip("requires an explicitly configured, isolated local test daemon")
	}
	cases := []struct {
		name, payload string
		want          Verdict
	}{
		{"benign", "wardveil integration test ordinary benign content\n", Clean},
		{"synthetic_detection", "wardveil-integration-test-detection-fixture-2026\n", Malicious},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := []byte(tc.payload)
			digest := sha256.Sum256(payload)
			request := Request{
				SchemaVersion: SchemaVersion,
				RequestID:     "test-" + tc.name,
				OwnerProduct:  "wardveil-lab",
				ObjectID:      "synthetic-fixture",
				SHA256:        hex.EncodeToString(digest[:]),
				SizeBytes:     int64(len(payload)),
				RequestedAt:   time.Now().UTC(),
			}
			result, err := (Clamd{
				SocketPath: socket,
				MaxBytes:   1024,
				Timeout:    5 * time.Second,
			}).Scan(context.Background(), request, io.NopCloser(bytes.NewReader(payload)))
			if err != nil {
				t.Fatal(err)
			}
			if result.Verdict != tc.want || result.Engine != "clamav" ||
				result.EngineVersion == "" {
				t.Fatalf("unexpected real-engine result: %+v", result)
			}
			if err := result.ValidateFor(request, time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			if tc.want == Malicious {
				if !strings.HasPrefix(result.SignatureID, "Wardveil.Test.Fixture") ||
					Recommend(result.Verdict) != RetainPendingReview {
					t.Fatalf("unsafe or unexpected detection: %+v", result)
				}
			} else if result.SignatureID != "" || Recommend(result.Verdict) != EligibleForOwnerReview {
				t.Fatalf("unexpected clean fixture disposition: %+v", result)
			}
			t.Logf("real clamd engine=%s verdict=%s signature=%q", result.EngineVersion, result.Verdict, result.SignatureID)
		})
	}
}
