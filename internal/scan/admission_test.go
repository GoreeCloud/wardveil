//go:build linux

package scan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type admissionFunc func(context.Context, VerifiedCaller, HeldObject, Request) error

func (fn admissionFunc) Reserve(ctx context.Context, caller VerifiedCaller, held HeldObject, req Request) error {
	return fn(ctx, caller, held, req)
}

func testScanLimiter() *ScanLimiter {
	limiter, err := NewScanLimiter(2)
	if err != nil {
		panic(err)
	}
	return limiter
}

func TestFileAdmissionPersistentReplayDenial(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private-admission")
	journal, err := OpenFileAdmission(dir)
	if err != nil {
		t.Fatal(err)
	}
	req := coordinatorRequest([]byte("safe synthetic content"))
	caller := VerifiedCaller{OwnerProduct: req.OwnerProduct, Subject: "test:service"}
	held := coordinatorHeld(req, io.NopCloser(bytes.NewReader(nil)))
	if err := journal.Reserve(context.Background(), caller, held, req); err != nil {
		t.Fatalf("first admission rejected: %v", err)
	}
	if err := journal.Reserve(context.Background(), caller, held, req); !errors.Is(err, ErrAdmissionReplay) {
		t.Fatalf("duplicate admission not rejected: %v", err)
	}
	journal2, err := OpenFileAdmission(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal2.Reserve(context.Background(), caller, held, req); !errors.Is(err, ErrAdmissionReplay) {
		t.Fatalf("restart admitted duplicate: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("admission marker count incorrect: entries=%v err=%v", entries, err)
	}
	info, err := entries[0].Info()
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("admission marker must be private 0600: %v err=%v", info, err)
	}
	body, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil || !bytes.Equal(body, []byte("wardveil-scan-admitted-v1\n")) {
		t.Fatal("admission marker may contain only fixed non-sensitive metadata")
	}
	if strings.Contains(entries[0].Name(), req.OwnerProduct) ||
		strings.Contains(entries[0].Name(), held.LeaseID) ||
		strings.Contains(string(body), req.ObjectID) {
		t.Fatal("private identifiers leaked to filename/marker body")
	}
	// Reusing the same lease with a fresh RequestID must still be blocked.
	another := req
	another.RequestID = "request:another"
	if err := journal2.Reserve(context.Background(), caller, held, another); !errors.Is(err, ErrAdmissionReplay) {
		t.Fatal("owner lease replay with new request ID must be denied")
	}
	// A separately verified, new owner-created pending lease is eligible.
	held.LeaseID = "pending:fresh-lease"
	if err := journal2.Reserve(context.Background(), caller, held, another); err != nil {
		t.Fatalf("new owner lease denied: %v", err)
	}
}

func TestFileAdmissionPrivateDirectoryAndScope(t *testing.T) {
	parent := t.TempDir()
	private := filepath.Join(parent, "private")
	if _, err := OpenFileAdmission("relative/path"); err == nil {
		t.Fatal("relative path accepted")
	}
	if err := os.Mkdir(private, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileAdmission(private); err == nil {
		t.Fatal("world-readable directory accepted")
	}
	if err := os.Chmod(private, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(private, filepath.Join(parent, "symlink")); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileAdmission(filepath.Join(parent, "symlink")); err == nil {
		t.Fatal("symlinked admission directory accepted")
	}
	journal, err := OpenFileAdmission(private)
	if err != nil {
		t.Fatal(err)
	}
	req := coordinatorRequest([]byte("hello"))
	held := coordinatorHeld(req, io.NopCloser(bytes.NewReader(nil)))
	caller := VerifiedCaller{OwnerProduct: req.OwnerProduct, Subject: "test:service"}
	for _, tc := range []struct {
		name   string
		change func()
	}{
		{"cross_product", func() { caller.OwnerProduct = "intruder" }},
		{"invalid_subject", func() { caller.Subject = "" }},
		{"bad_lease", func() { held.LeaseID = "../forged" }},
		{"not_pending", func() { held.Pending = false }},
		{"wrong_digest", func() { held.SHA256 = strings.Repeat("0", 64) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			held = coordinatorHeld(req, nil)
			caller = VerifiedCaller{OwnerProduct: req.OwnerProduct, Subject: "test:service"}
			tc.change()
			if err := journal.Reserve(context.Background(), caller, held, req); err == nil {
				t.Fatal("invalid held admission accepted")
			}
		})
	}
	entries, err := os.ReadDir(private)
	if err != nil || len(entries) != 0 {
		t.Fatalf("bad admissions should create no markers: %v %v", entries, err)
	}
}

func TestFileAdmissionConcurrentDuplicateAtomicity(t *testing.T) {
	journal, err := OpenFileAdmission(filepath.Join(t.TempDir(), "leases"))
	if err != nil {
		t.Fatal(err)
	}
	req := coordinatorRequest([]byte("fixture"))
	held := coordinatorHeld(req, nil)
	caller := VerifiedCaller{OwnerProduct: req.OwnerProduct, Subject: "test:service"}
	var allowed, rejected, other atomic.Int64
	const attempts = 48
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := journal.Reserve(context.Background(), caller, held, req)
			switch {
			case err == nil:
				allowed.Add(1)
			case errors.Is(err, ErrAdmissionReplay):
				rejected.Add(1)
			default:
				other.Add(1)
			}
		}()
	}
	wg.Wait()
	if allowed.Load() != 1 || rejected.Load() != attempts-1 || other.Load() != 0 {
		t.Fatalf("non-atomic admission: allowed=%d rejected=%d other=%d", allowed.Load(), rejected.Load(), other.Load())
	}
}

func TestScanLimiterImmediateBackpressureAndOnceRelease(t *testing.T) {
	for _, n := range []int{-1, 0, 33} {
		if _, err := NewScanLimiter(n); err == nil {
			t.Fatalf("unsafe concurrency limit %d accepted", n)
		}
	}
	limiter, err := NewScanLimiter(1)
	if err != nil {
		t.Fatal(err)
	}
	release, err := limiter.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := limiter.Acquire(context.Background()); !errors.Is(err, ErrScanBusy) {
		t.Fatalf("expected immediate capacity rejection, got %v", err)
	}
	release()
	release() // must not over-release slots
	release2, err := limiter.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := limiter.Acquire(context.Background()); !errors.Is(err, ErrScanBusy) {
		t.Fatal("once-only release violated")
	}
	release2()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := limiter.Acquire(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled acquire accepted: %v", err)
	}
	if _, err := (*ScanLimiter)(nil).Acquire(context.Background()); err == nil {
		t.Fatal("nil limiter accepted")
	}
}

func TestFileAdmissionIncompleteMarkerFailsClosed(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "journal")
	store, err := OpenFileAdmission(dir)
	if err != nil {
		t.Fatal(err)
	}
	req := coordinatorRequest([]byte("content"))
	caller := VerifiedCaller{OwnerProduct: req.OwnerProduct, Subject: "test:service"}
	held := coordinatorHeld(req, nil)
	// Simulate a previous worker crashing after O_EXCL but before fsync.
	hash := sha256.Sum256([]byte(caller.OwnerProduct + "\x00" + held.LeaseID))
	incomplete := filepath.Join(dir, hex.EncodeToString(hash[:])+".admitted")
	if err := os.WriteFile(incomplete, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.Reserve(context.Background(), caller, held, req); !errors.Is(err, ErrAdmissionReplay) {
		t.Fatalf("incomplete old marker was treated as new: %v", err)
	}
	fi, err := os.Stat(incomplete)
	if err != nil || fi.Size() != 0 {
		t.Fatalf("crashed marker was modified: %v %v", fi, err)
	}
}

func TestFileAdmissionRejectsUnsafePermissionChange(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "journal")
	store, err := OpenFileAdmission(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0700)
	req := coordinatorRequest([]byte("fixture"))
	caller := VerifiedCaller{OwnerProduct: req.OwnerProduct, Subject: "test:service"}
	held := coordinatorHeld(req, nil)
	if err := store.Reserve(context.Background(), caller, held, req); err == nil {
		t.Fatal("unsafe permission drift accepted")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatal("unsafe marker written despite permission drift")
	}
}
