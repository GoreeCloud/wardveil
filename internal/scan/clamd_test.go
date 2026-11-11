package scan

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeClamd struct {
	socket string
	mu     sync.Mutex
	frames [][]byte
}

// makeScannerDaemon is a fake local daemon. No real antivirus is used here;
// integration with a real clamd and sandbox is a separate release gate.
func makeScannerDaemon(t *testing.T, versionReply, scanReply string, hang bool) *fakeClamd {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "scan.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	fake := &fakeClamd{socket: socket}
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				reader := bufio.NewReader(c)
				command, err := reader.ReadBytes(0)
				if err != nil {
					return
				}
				switch string(command) {
				case "zVERSION\x00":
					_, _ = io.WriteString(c, versionReply+"\x00")
				case "zINSTREAM\x00":
					var received bytes.Buffer
					for {
						var length uint32
						if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
							return
						}
						if length == 0 {
							break
						}
						if length > 1<<20 {
							return
						}
						if _, err := io.CopyN(&received, reader, int64(length)); err != nil {
							return
						}
					}
					fake.mu.Lock()
					fake.frames = append(fake.frames, append([]byte(nil), received.Bytes()...))
					fake.mu.Unlock()
					if hang {
						_, _ = io.Copy(io.Discard, c)
						return
					}
					_, _ = io.WriteString(c, scanReply+"\x00")
				}
			}()
		}
	}()
	return fake
}

func testScanRequest(payload []byte) Request {
	now := time.Now().UTC().Truncate(time.Second)
	sum := sha256.Sum256(payload)
	return Request{
		SchemaVersion: SchemaVersion,
		RequestID:     "req:001",
		OwnerProduct:  "notebook",
		ObjectID:      "object:001",
		SHA256:        hex.EncodeToString(sum[:]),
		SizeBytes:     int64(len(payload)),
		RequestedAt:   now,
	}
}

func TestClamdINSTREAMVerdicts(t *testing.T) {
	payload := []byte(strings.Repeat("read-only-fixture", 3000))
	cases := []struct {
		name, response string
		want           Verdict
		sig            string
	}{
		{"clean", "stream: OK", Clean, ""},
		{"detected", "stream: Eicar.Test-1 FOUND", Malicious, "Eicar.Test-1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := makeScannerDaemon(t, "ClamAV 1.4.3/27340/Fri Nov 6 2026", tc.response, false)
			result, err := (Clamd{SocketPath: f.socket}).Scan(context.Background(), testScanRequest(payload), io.NopCloser(bytes.NewReader(payload)))
			if err != nil {
				t.Fatal(err)
			}
			if result.Verdict != tc.want || result.SignatureID != tc.sig || result.Engine != "clamav" || result.EngineVersion != "1.4.3" {
				t.Fatalf("bad result: %+v", result)
			}
			if Recommend(result.Verdict) == EligibleForOwnerReview && tc.want != Clean {
				t.Fatal("unexpected eligible disposition")
			}
			f.mu.Lock()
			got := append([][]byte(nil), f.frames...)
			f.mu.Unlock()
			if len(got) != 1 || !bytes.Equal(got[0], payload) {
				t.Fatalf("bad INSTREAM framing: %d records", len(got))
			}
		})
	}
}

func TestClamdRejectsUntrustedInput(t *testing.T) {
	payload := []byte("benign-fixture")
	base := testScanRequest(payload)
	for _, tc := range []struct {
		name string
		req  Request
		data []byte
		conf Clamd
	}{
		{"truncated", base, payload[:5], Clamd{}},
		{"extra_data", base, append(append([]byte{}, payload...), 'x'), Clamd{}},
		{"hash_mismatch", func() Request { r := base; r.SHA256 = strings.Repeat("a", 64); return r }(), payload, Clamd{}},
		{"size_limit", base, payload, Clamd{MaxBytes: 4}},
		{"bad_timeout", base, payload, Clamd{Timeout: -1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := makeScannerDaemon(t, "ClamAV 1.4.3/123/now", "stream: OK", false)
			tc.conf.SocketPath = f.socket
			_, err := tc.conf.Scan(context.Background(), tc.req, io.NopCloser(bytes.NewReader(tc.data)))
			if err == nil {
				t.Fatal("expected scan to fail closed")
			}
		})
	}
}

func TestClamdRejectsUnsafeReplies(t *testing.T) {
	payload := []byte("fixture")
	for _, reply := range []string{
		"stream: access denied ERROR",
		"stream: OKAY",
		"stream: Eicar.Test FOUND extra",
		"stream: OK\x00stream: Eicar.Test FOUND",
		"stream: Eicar.Test FOUND\x00stream: OK",
		"stream: bad/signature FOUND",
		"stream: ",
	} {
		t.Run(fmt.Sprintf("%q", reply), func(t *testing.T) {
			f := makeScannerDaemon(t, "ClamAV 1.4.3/123/now", reply, false)
			_, err := (Clamd{SocketPath: f.socket}).Scan(context.Background(), testScanRequest(payload), io.NopCloser(bytes.NewReader(payload)))
			if err == nil {
				t.Fatal("unsafe clamd reply accepted")
			}
		})
	}
	t.Run("version_command_disabled", func(t *testing.T) {
		f := makeScannerDaemon(t, "COMMAND UNAVAILABLE", "stream: OK", false)
		_, err := (Clamd{SocketPath: f.socket}).Scan(context.Background(), testScanRequest(payload), io.NopCloser(bytes.NewReader(payload)))
		if err == nil {
			t.Fatal("unverified engine version accepted")
		}
	})
	t.Run("scanner_timeout", func(t *testing.T) {
		f := makeScannerDaemon(t, "ClamAV 1.4.3/123/now", "stream: OK", true)
		_, err := (Clamd{SocketPath: f.socket, Timeout: 60 * time.Millisecond}).Scan(context.Background(), testScanRequest(payload), io.NopCloser(bytes.NewReader(payload)))
		if err == nil {
			t.Fatal("scanner timeout accepted")
		}
	})
	t.Run("missing_socket", func(t *testing.T) {
		_, err := (Clamd{SocketPath: filepath.Join(t.TempDir(), "absent.sock")}).Scan(context.Background(), testScanRequest(payload), io.NopCloser(bytes.NewReader(payload)))
		if err == nil {
			t.Fatal("offline daemon accepted")
		}
	})
}

func TestClamdClosesStalledSourceOnTimeout(t *testing.T) {
	f := makeScannerDaemon(t, "ClamAV 1.4.3/123/now", "stream: OK", false)
	reader, writer := io.Pipe()
	defer writer.Close()
	start := time.Now()
	_, err := (Clamd{SocketPath: f.socket, Timeout: 75 * time.Millisecond}).Scan(context.Background(), testScanRequest([]byte("x")), reader)
	if err == nil {
		t.Fatal("stalled source was accepted")
	}
	if time.Since(start) > time.Second {
		t.Fatal("scan cancellation did not close source promptly")
	}
}
