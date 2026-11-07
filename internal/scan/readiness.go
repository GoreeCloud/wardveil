package scan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ScanReadiness gates access to owner-held bytes. A caller-supplied file,
// HTTP request, or claimed successful scan is never trusted readiness evidence.
type ScanReadiness interface {
	Check(context.Context) error
}

const (
	defaultMaxDailyAge      = 72 * time.Hour
	defaultReadinessTimeout = 8 * time.Second
	maxSigtoolInfoBytes     = 8192
)

// VerifiedCVDReadiness is a narrow, deliberately conservative pre-scan gate.
// It requires both main.cvd and daily.cvd and an installed trusted, current
// ClamAV sigtool that prints "Verification OK." for each CVD signature.
// It rejects .cld databases: a separate FreshClam-provenance adapter must
// be independently designed before those update formats can be accepted.
// This component does not install or update signatures.
type VerifiedCVDReadiness struct {
	Clamd             Clamd
	SigtoolPath       string
	DatabaseDirectory string
	MaxDailyAge       time.Duration
	Timeout           time.Duration
}

type cvdInfo struct {
	version    uint64
	buildTime  time.Time
	signatures uint64
}

func (v VerifiedCVDReadiness) Check(ctx context.Context) error {
	if ctx == nil {
		return errors.New("readiness context required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !filepath.IsAbs(v.SigtoolPath) || !filepath.IsAbs(v.DatabaseDirectory) ||
		strings.ContainsRune(v.SigtoolPath, '\x00') || strings.ContainsRune(v.DatabaseDirectory, '\x00') {
		return errors.New("readiness requires absolute trusted paths")
	}
	maxAge := v.MaxDailyAge
	if maxAge == 0 {
		maxAge = defaultMaxDailyAge
	}
	if maxAge < time.Hour || maxAge > 7*24*time.Hour {
		return errors.New("invalid maximum signature age")
	}
	timeout := v.Timeout
	if timeout == 0 {
		timeout = defaultReadinessTimeout
	}
	if timeout < 100*time.Millisecond || timeout > 30*time.Second {
		return errors.New("invalid signature verification timeout")
	}
	if err := checkTrustedReadinessFile(v.SigtoolPath); err != nil {
		return errors.New("trusted signature verification tool unavailable or unsafe")
	}
	dir, err := os.Lstat(v.DatabaseDirectory)
	if err != nil || !dir.IsDir() || dir.Mode().Perm()&0022 != 0 {
		return errors.New("signature database directory unavailable or unsafe")
	}
	// Do not attest a directory that could also load unsigned CLD or custom
	// signatures in addition to the verified CVDs. This intentionally
	// restrictive reference mode requires a dedicated two-file database.
	if err := checkStrictCVDDirectory(v.DatabaseDirectory); err != nil {
		return err
	}
	subctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	main, err := v.verifyCVD(subctx, "main.cvd")
	if err != nil {
		return fmt.Errorf("main CVD readiness rejected: %w", err)
	}
	daily, err := v.verifyCVD(subctx, "daily.cvd")
	if err != nil {
		return fmt.Errorf("daily CVD readiness rejected: %w", err)
	}
	if main.signatures == 0 || daily.signatures == 0 {
		return errors.New("verified signature databases contain no signatures")
	}
	now := time.Now().UTC()
	if daily.buildTime.After(now.Add(5*time.Minute)) || now.Sub(daily.buildTime) > maxAge {
		return errors.New("official daily signature database is missing a recent build time")
	}
	if main.buildTime.After(now.Add(5 * time.Minute)) {
		return errors.New("main signature database build time is in the future")
	}
	// A verified on-disk CVD is not sufficient if clamd still runs an old
	// database. Require the live daemon to report exactly the verified daily
	// CVD version. A local Unix socket still needs restricted ownership.
	loaded, err := v.Clamd.databaseVersion(subctx)
	if err != nil {
		return errors.New("running clamd signature version unavailable")
	}
	if loaded != daily.version {
		return errors.New("running clamd signature version differs from verified daily CVD")
	}
	return subctx.Err()
}

func checkTrustedReadinessFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0111 == 0 {
		return errors.New("unsafe or nonexecutable trusted file")
	}
	return nil
}

func (v VerifiedCVDReadiness) verifyCVD(ctx context.Context, file string) (cvdInfo, error) {
	path := filepath.Join(v.DatabaseDirectory, file)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return cvdInfo{}, errors.New("required private signed CVD file missing or unsafe")
	}
	// No shell, network, arbitrary filename or caller-provided arguments.
	// The installed sigtool binary and its deployment provenance MUST be
	// verified by the operator; fake test binaries are synthetic only.
	cmd := exec.CommandContext(ctx, v.SigtoolPath, "--info", path)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	var output bytes.Buffer
	limited := &boundedInfoWriter{out: &output}
	cmd.Stdout = limited
	cmd.Stderr = limited
	if err := cmd.Run(); err != nil {
		return cvdInfo{}, errors.New("sigtool could not verify CVD")
	}
	return parseVerifiedCVDInfo(output.String())
}

type boundedInfoWriter struct {
	out  *bytes.Buffer
	used int
}

func (w *boundedInfoWriter) Write(p []byte) (int, error) {
	if len(p) > maxSigtoolInfoBytes-w.used {
		return 0, errors.New("signature verification output too large")
	}
	w.used += len(p)
	return w.out.Write(p)
}

func parseVerifiedCVDInfo(output string) (cvdInfo, error) {
	if len(output) > maxSigtoolInfoBytes || strings.ContainsRune(output, '\x00') {
		return cvdInfo{}, errors.New("invalid signature metadata")
	}
	var foundVersion, foundBuild, foundCount, verified bool
	var parsed cvdInfo
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "Verification OK." {
			if verified {
				return cvdInfo{}, errors.New("duplicate signature verification line")
			}
			verified = true
		}
		if strings.HasPrefix(line, "Version: ") {
			if foundVersion {
				return cvdInfo{}, errors.New("duplicate CVD version")
			}
			foundVersion = true
			n, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "Version: ")), 10, 32)
			if err != nil || n == 0 {
				return cvdInfo{}, errors.New("invalid CVD version")
			}
			parsed.version = n
		}
		if strings.HasPrefix(line, "Signatures: ") {
			if foundCount {
				return cvdInfo{}, errors.New("duplicate CVD signature count")
			}
			foundCount = true
			n, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "Signatures: ")), 10, 32)
			if err != nil || n == 0 {
				return cvdInfo{}, errors.New("invalid CVD signature count")
			}
			parsed.signatures = n
		}
		if strings.HasPrefix(line, "Build time: ") {
			if foundBuild {
				return cvdInfo{}, errors.New("duplicate CVD build time")
			}
			foundBuild = true
			rawTime := strings.TrimSpace(strings.TrimPrefix(line, "Build time: "))
			t, err := time.Parse("02 Jan 2006 15:04 -0700", rawTime)
			if err != nil {
				return cvdInfo{}, errors.New("invalid CVD build time")
			}
			parsed.buildTime = t.UTC()
		}
	}
	if !verified || !foundVersion || !foundBuild || !foundCount {
		return cvdInfo{}, errors.New("unverified or missing CVD metadata")
	}
	return parsed, nil
}

// databaseVersion queries the actual local daemon. Custom-signature-only
// labs may return only an engine version; that is not official CVD evidence.
func (c Clamd) databaseVersion(ctx context.Context) (uint64, error) {
	reply, err := c.versionReply(ctx)
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(reply)
	if len(fields) < 2 || fields[0] != "ClamAV" {
		return 0, errors.New("invalid clamd VERSION response")
	}
	parts := strings.SplitN(fields[1], "/", 3)
	if len(parts) < 2 || !identifier.MatchString(parts[0]) {
		return 0, errors.New("clamd does not report an official database version")
	}
	n, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil || n == 0 {
		return 0, errors.New("invalid clamd database version")
	}
	return n, nil
}

func (c Clamd) versionReply(ctx context.Context) (string, error) {
	if _, _, err := c.settings(); err != nil {
		return "", err
	}
	conn, err := c.connect(ctx)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if _, err := io.WriteString(conn, "zVERSION\x00"); err != nil {
		return "", err
	}
	return readRecord(conn)
}

// checkStrictCVDDirectory rejects all extra files, subdirectories and
// symlinks. A CVD-only deployment must not silently load daily.cld,
// bytecode/custom .hdb/.ldb/.ndb, or other unverified databases.
// Full FreshClam-managed installations need a separately audited verifier.
func checkStrictCVDDirectory(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return errors.New("cannot enumerate ClamAV signature database directory")
	}
	if len(entries) != 2 {
		return errors.New("strict CVD mode requires exactly main.cvd and daily.cvd")
	}
	var main, daily bool
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			return errors.New("strict CVD database contains a non-regular entry")
		}
		switch entry.Name() {
		case "main.cvd":
			main = true
		case "daily.cvd":
			daily = true
		default:
			return errors.New("strict CVD database contains unverified extra content")
		}
	}
	if !main || !daily {
		return errors.New("strict CVD database is incomplete")
	}
	return nil
}
