package scan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type readinessFunc func(context.Context) error

func (f readinessFunc) Check(ctx context.Context) error { return f(ctx) }

// syntheticReadiness is TEST ONLY and must never be used for a real source product.
func syntheticReadiness() ScanReadiness {
	return readinessFunc(func(context.Context) error { return nil })
}

func TestCVDMetadataRejectsUnsignedAndMalformed(t *testing.T) {
	build := time.Now().UTC().Add(-time.Hour).Format("02 Jan 2006 15:04 -0700")
	valid := fmt.Sprintf("Build time: %s\nVersion: 12345\nSignatures: 900\nVerification OK.\n", build)
	parsed, err := parseVerifiedCVDInfo(valid)
	if err != nil || parsed.version != 12345 || parsed.signatures != 900 {
		t.Fatalf("valid signed metadata rejected: %+v %v", parsed, err)
	}
	for _, tc := range []struct{ name, body string }{
		{"missing_verification", strings.ReplaceAll(valid, "Verification OK.", "Verification FAILED.")},
		{"fake_prefix", strings.ReplaceAll(valid, "Verification OK.", "Message: Verification OK.")},
		{"duplicate_verification", valid + "Verification OK.\n"},
		{"missing_date", strings.Replace(valid, "Build time: "+build+"\n", "", 1)},
		{"invalid_date", strings.Replace(valid, build, "yesterday", 1)},
		{"missing_count", strings.Replace(valid, "Signatures: 900\n", "", 1)},
		{"zero_signatures", strings.Replace(valid, "Signatures: 900", "Signatures: 0", 1)},
		{"duplicate_version", valid + "Version: 777\n"},
		{"nondecimal_version", strings.Replace(valid, "Version: 12345", "Version: no", 1)},
		{"null_byte", valid + "\x00"},
		{"huge_info", valid + strings.Repeat("x", maxSigtoolInfoBytes)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseVerifiedCVDInfo(tc.body); err == nil {
				t.Fatal("malformed or unsigned CVD metadata accepted")
			}
		})
	}
}

func fakeClamdVersion(t *testing.T, initial string) (string, func(string)) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "clamd.sock")
	lis, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.RWMutex
	reply := initial
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				got := make([]byte, len("zVERSION\x00"))
				if _, err := io.ReadFull(c, got); err == nil && bytes.Equal(got, []byte("zVERSION\x00")) {
					mu.RLock()
					s := reply
					mu.RUnlock()
					_, _ = io.WriteString(c, s+"\x00")
				}
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = lis.Close(); wg.Wait() })
	return path, func(s string) { mu.Lock(); reply = s; mu.Unlock() }
}

func fakeSignedCVDs(t *testing.T, age time.Duration, signed bool) VerifiedCVDReadiness {
	t.Helper()
	root := t.TempDir()
	db := filepath.Join(root, "db")
	if err := os.Mkdir(db, 0700); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"main.cvd", "daily.cvd"} {
		if err := os.WriteFile(filepath.Join(db, p), []byte("fake bytes, no real CVD signature"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	verify := "Verification OK."
	if !signed {
		verify = "Verification FAILED."
	}
	dailyDate := time.Now().UTC().Add(-age).Format("02 Jan 2006 15:04 -0700")
	mainDate := time.Now().UTC().Add(-60 * 24 * time.Hour).Format("02 Jan 2006 15:04 -0700")
	// This fixture is a fake executable, NOT real sigtool. Live acceptance
	// requires official CVDs verified by the installed genuine ClamAV utility.
	script := "#!/bin/sh\ncase \"$1\" in --info) ;; *) exit 2 ;; esac\ncase \"$2\" in\n" +
		"  */daily.cvd) printf 'Build time: " + dailyDate + "\\nVersion: 12345\\nSignatures: 100\\n" + verify + "\\n' ;;\n" +
		"  */main.cvd) printf 'Build time: " + mainDate + "\\nVersion: 1\\nSignatures: 100\\n" + verify + "\\n' ;;\n" +
		"  *) exit 2 ;;\nesac\n"
	exe := filepath.Join(root, "fake-sigtool")
	if err := os.WriteFile(exe, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	socket, _ := fakeClamdVersion(t, "ClamAV 1.4.6/12345/Sat")
	return VerifiedCVDReadiness{Clamd: Clamd{SocketPath: socket, Timeout: 2 * time.Second},
		SigtoolPath: exe, DatabaseDirectory: db, MaxDailyAge: 72 * time.Hour, Timeout: 2 * time.Second}
}

func TestVerifiedCVDGateWithTestOnlySigner(t *testing.T) {
	gate := fakeSignedCVDs(t, 3*time.Hour, true)
	if err := gate.Check(context.Background()); err != nil {
		t.Fatalf("synthetic recent CVD info rejected: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := gate.Check(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled check passed: %v", err)
	}
}
func TestVerifiedCVDGateRefusesUnsafeStates(t *testing.T) {
	cases := []struct {
		name   string
		age    time.Duration
		signed bool
		mutate func(*testing.T, *VerifiedCVDReadiness)
	}{
		{"stale_daily", 100 * time.Hour, true, nil},
		{"future_daily", -3 * time.Hour, true, nil},
		{"unsigned", time.Hour, false, nil},
		{"missing_daily", time.Hour, true, func(t *testing.T, v *VerifiedCVDReadiness) {
			_ = os.Remove(filepath.Join(v.DatabaseDirectory, "daily.cvd"))
		}},
		{"symlink_daily", time.Hour, true, func(t *testing.T, v *VerifiedCVDReadiness) {
			p := filepath.Join(v.DatabaseDirectory, "daily.cvd")
			_ = os.Remove(p)
			if err := os.Symlink(filepath.Join(v.DatabaseDirectory, "main.cvd"), p); err != nil {
				t.Fatal(err)
			}
		}},
		{"writable_daily", time.Hour, true, func(t *testing.T, v *VerifiedCVDReadiness) {
			if err := os.Chmod(filepath.Join(v.DatabaseDirectory, "daily.cvd"), 0666); err != nil {
				t.Fatal(err)
			}
		}},
		{"writable_dir", time.Hour, true, func(t *testing.T, v *VerifiedCVDReadiness) {
			if err := os.Chmod(v.DatabaseDirectory, 0777); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink_sigtool", time.Hour, true, func(t *testing.T, v *VerifiedCVDReadiness) {
			p := v.SigtoolPath
			v.SigtoolPath = p + ".link"
			if err := os.Symlink(p, v.SigtoolPath); err != nil {
				t.Fatal(err)
			}
		}},
		{"missing_socket", time.Hour, true, func(t *testing.T, v *VerifiedCVDReadiness) {
			v.Clamd.SocketPath = filepath.Join(t.TempDir(), "missing.sock")
		}},
		{"invalid_age", time.Hour, true, func(t *testing.T, v *VerifiedCVDReadiness) { v.MaxDailyAge = 8 * 24 * time.Hour }},
		{"invalid_timeout", time.Hour, true, func(t *testing.T, v *VerifiedCVDReadiness) { v.Timeout = 31 * time.Second }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gate := fakeSignedCVDs(t, tc.age, tc.signed)
			if tc.mutate != nil {
				tc.mutate(t, &gate)
			}
			if err := gate.Check(context.Background()); err == nil {
				t.Fatal("unsafe metadata or origin accepted")
			}
		})
	}
}

func TestReadinessRejectsBeforeSourceOwnerOrAdmission(t *testing.T) {
	data := []byte("test bytes")
	req := coordinatorRequest(data)
	for _, tc := range []struct {
		name  string
		check ScanReadiness
	}{
		{"missing_checker", nil},
		{"unverified", readinessFunc(func(context.Context) error { return errors.New("secret internal verification failure") })},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opens, admits, scans, records := 0, 0, 0, 0
			w := ScanCoordinator{Readiness: tc.check, Auth: coordinatorAuth(), Capacity: testScanLimiter(),
				Source: sourceOwnerFunc(func(context.Context, VerifiedCaller, Request) (HeldObject, error) {
					opens++
					return coordinatorHeld(req, io.NopCloser(bytes.NewReader(data))), nil
				}),
				Admission: admissionFunc(func(context.Context, VerifiedCaller, HeldObject, Request) error { admits++; return nil }),
				Engine: malwareEngineFunc(func(context.Context, Request, io.ReadCloser) (Result, error) {
					scans++
					return coordinatorResult(req, Clean), nil
				}),
				Record: recordFunc(func(context.Context, VerifiedCaller, string, Request, Result, Disposition) error {
					records++
					return nil
				})}
			result, err := w.Process(context.Background(), []byte("authorized-fixture"), req)
			if err == nil || result != (ScanAdvice{}) || opens != 0 || admits != 0 || scans != 0 || records != 0 {
				t.Fatalf("readiness fail-open: result=%+v err=%v counts=%d/%d/%d/%d", result, err, opens, admits, scans, records)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatal("leaked verifier internals")
			}
		})
	}
}

func TestClamdSyntheticLabNotOfficialReady(t *testing.T) {
	socket := os.Getenv("WARDVEIL_CLAMD_TEST_SOCKET")
	if socket == "" {
		t.Skip("requires explicitly isolated synthetic-only ClamAV lab")
	}
	clamd := Clamd{SocketPath: socket, Timeout: 5 * time.Second}
	version, err := clamd.version(context.Background())
	if err != nil || version == "" {
		t.Fatalf("synthetic lab has no ClamAV engine: %q %v", version, err)
	}
	if db, err := clamd.databaseVersion(context.Background()); err == nil {
		t.Fatalf("synthetic custom-signature-only ClamAV unexpectedly reported official CVD version %d", db)
	}
}

func TestVerifiedCVDLoadedDaemonVersionMustMatch(t *testing.T) {
	gate := fakeSignedCVDs(t, time.Hour, true)
	socket, set := fakeClamdVersion(t, "ClamAV 1.4.6/100/different-db")
	gate.Clamd.SocketPath = socket
	if err := gate.Check(context.Background()); err == nil {
		t.Fatal("signed on-disk database did not match running engine database")
	}
	set("ClamAV 1.4.6")
	if err := gate.Check(context.Background()); err == nil {
		t.Fatal("custom-only daemon falsely accepted as official signature ready")
	}
	set("ClamAV 1.4.6/12345/date")
	if err := gate.Check(context.Background()); err != nil {
		t.Fatalf("matched daemon/database should pass synthetic metadata test: %v", err)
	}
}

func TestVerifiedCVDMissingMainFails(t *testing.T) {
	gate := fakeSignedCVDs(t, time.Hour, true)
	if err := os.Remove(filepath.Join(gate.DatabaseDirectory, "main.cvd")); err != nil {
		t.Fatal(err)
	}
	if err := gate.Check(context.Background()); err == nil {
		t.Fatal("missing signed main CVD must be rejected")
	}
}

func TestReadinessUsesScanCapacityBeforeStartingVerification(t *testing.T) {
	payload := []byte("synthetic held file")
	req := coordinatorRequest(payload)
	limit, err := NewScanLimiter(1)
	if err != nil {
		t.Fatal(err)
	}
	occupied, err := limit.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	checks, opens, admissions, scans, records := 0, 0, 0, 0, 0
	worker := ScanCoordinator{
		Auth:     coordinatorAuth(),
		Capacity: limit,
		Readiness: readinessFunc(func(context.Context) error {
			checks++
			return errors.New("unverified signatures")
		}),
		Source: sourceOwnerFunc(func(context.Context, VerifiedCaller, Request) (HeldObject, error) {
			opens++
			return coordinatorHeld(req, io.NopCloser(bytes.NewReader(payload))), nil
		}),
		Admission: admissionFunc(func(context.Context, VerifiedCaller, HeldObject, Request) error {
			admissions++
			return nil
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
	out, err := worker.Process(context.Background(), []byte("authorized-fixture"), req)
	if !errors.Is(err, ErrScanBusy) || out != (ScanAdvice{}) || checks != 0 ||
		opens != 0 || admissions != 0 || scans != 0 || records != 0 {
		t.Fatalf("saturated scanner allowed readiness: %+v err=%v checks=%d", out, err, checks)
	}
	occupied()
	for i := 0; i < 2; i++ {
		out, err = worker.Process(context.Background(), []byte("authorized-fixture"), req)
		if err == nil || out != (ScanAdvice{}) || checks != i+1 ||
			opens != 0 || admissions != 0 || scans != 0 || records != 0 {
			t.Fatalf("readiness failure leaked a capacity slot or accessed source: %+v err=%v checks=%d", out, err, checks)
		}
	}
}

func TestConcurrentReadinessNeverExceedsLocalScanLimit(t *testing.T) {
	payload := []byte("test bytes")
	req := coordinatorRequest(payload)
	limit, err := NewScanLimiter(1)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	var checks, opened, recorded atomic.Int64
	worker := ScanCoordinator{
		Auth:     coordinatorAuth(),
		Capacity: limit,
		Readiness: readinessFunc(func(context.Context) error {
			if checks.Add(1) == 1 {
				close(started)
			}
			<-release
			return errors.New("synthetic unready")
		}),
		Source: sourceOwnerFunc(func(context.Context, VerifiedCaller, Request) (HeldObject, error) {
			opened.Add(1)
			return HeldObject{}, errors.New("no owner access allowed")
		}),
		Admission: admissionFunc(func(context.Context, VerifiedCaller, HeldObject, Request) error {
			t.Error("admission attempted during readiness failure")
			return nil
		}),
		Engine: malwareEngineFunc(func(context.Context, Request, io.ReadCloser) (Result, error) {
			t.Error("engine invoked during readiness failure")
			return Result{}, nil
		}),
		Record: recordFunc(func(context.Context, VerifiedCaller, string, Request, Result, Disposition) error {
			recorded.Add(1)
			return nil
		}),
	}
	var leader sync.WaitGroup
	leader.Add(1)
	go func() {
		defer leader.Done()
		_, _ = worker.Process(context.Background(), []byte("authorized-fixture"), req)
	}()
	<-started
	const requests = 48
	results := make(chan error, requests)
	for i := 0; i < requests; i++ {
		go func() {
			_, e := worker.Process(context.Background(), []byte("authorized-fixture"), req)
			results <- e
		}()
	}
	for i := 0; i < requests; i++ {
		if e := <-results; !errors.Is(e, ErrScanBusy) {
			t.Fatalf("simultaneous request bypassed capacity: %v", e)
		}
	}
	close(release)
	leader.Wait()
	if checks.Load() != 1 || opened.Load() != 0 || recorded.Load() != 0 {
		t.Fatalf("unbounded readiness workers or owner disclosure: checks=%d opened=%d recorded=%d",
			checks.Load(), opened.Load(), recorded.Load())
	}
}

func TestStrictCVDModeRefusesCoexistingUnverifiedSignatureFiles(t *testing.T) {
	for _, tc := range []struct {
		name string
		add  func(*testing.T, string)
	}{
		{"unsigned_daily_cld", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "daily.cld"), []byte("unverified patch state"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"additional_bytecode_cvd", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "bytecode.cvd"), []byte("unverified archive"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"custom_hdb", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "custom.hdb"), []byte("unverified custom signatures"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"custom_ldb", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "custom.ldb"), []byte("unverified custom signatures"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"freshclam_state", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "freshclam.dat"), []byte("unverified update metadata"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"extra_directory", func(t *testing.T, dir string) {
			if err := os.Mkdir(filepath.Join(dir, "custom-sigs"), 0700); err != nil {
				t.Fatal(err)
			}
		}},
		{"unexpected_symlink", func(t *testing.T, dir string) {
			if err := os.Symlink(filepath.Join(dir, "main.cvd"), filepath.Join(dir, "shadow.cvd")); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gate := fakeSignedCVDs(t, time.Hour, true)
			tc.add(t, gate.DatabaseDirectory)
			if err := gate.Check(context.Background()); err == nil {
				t.Fatal("coexisting unverified database content accepted as signed CVD-only readiness")
			}
		})
	}
}

func TestStrictCVDModeRequiresOnlyTwoKnownRegularFiles(t *testing.T) {
	gate := fakeSignedCVDs(t, time.Hour, true)
	if err := checkStrictCVDDirectory(gate.DatabaseDirectory); err != nil {
		t.Fatalf("dedicated two-file CVD directory was rejected: %v", err)
	}
}
