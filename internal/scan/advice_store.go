package scan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

const maxAdviceReceiptBytes = 1536

var ErrAdviceAlreadyRecorded = errors.New("scan advice receipt already exists; owner review required")

// AdviceReceipt is private, minimally identified advisory evidence. It excludes
// credentials, subjects, raw object IDs, file hashes and file bytes. Its
// fingerprints are NOT cryptographic tamper protection or release authority.
type AdviceReceipt struct {
	SchemaVersion       string
	LeaseFingerprint    string
	EvidenceFingerprint string
	Verdict             Verdict
	Recommendation      Disposition
	Engine              string
	EngineVersion       string
	ScannedAt           time.Time
	RecordedAt          time.Time
}

// FileAdviceRecorder is a local development-only immutable per-lease receipt
// writer. Even a clean verdict never publishes, releases, or deletes files.
type FileAdviceRecorder struct{ dir string }

var _ AdvisoryRecorder = (*FileAdviceRecorder)(nil)

// Reuse the private directory, initial parent fsync and permission invariant
// from FileAdmission; operators should configure a separate receipt directory.
func OpenFileAdviceRecorder(dir string) (*FileAdviceRecorder, error) {
	if _, err := OpenFileAdmission(dir); err != nil {
		return nil, err
	}
	return &FileAdviceRecorder{dir: dir}, nil
}

func adviceLeaseFingerprint(owner, lease string) string {
	sum := sha256.Sum256([]byte(owner + string(rune(0)) + lease))
	return hex.EncodeToString(sum[:])
}
func (f *FileAdviceRecorder) check(ctx context.Context, caller VerifiedCaller, lease string) error {
	if ctx == nil {
		return errors.New("missing advice context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if f == nil || f.dir == "" {
		return errors.New("advice recorder not configured")
	}
	if !identifier.MatchString(caller.OwnerProduct) || !identifier.MatchString(caller.Subject) || !identifier.MatchString(lease) {
		return errors.New("invalid advice owner or lease scope")
	}
	if err := checkPrivateAdmissionDirectory(f.dir); err != nil {
		return fmt.Errorf("private advice directory unavailable: %w", err)
	}
	return nil
}

// RecordAdvice requires exact object/owner/result binding and the nonrelease
// recommendation. Ambiguous I/O or existing markers fail closed. No scan
// credentials, source file content or identifying plaintext is persisted.
func (f *FileAdviceRecorder) RecordAdvice(ctx context.Context, caller VerifiedCaller, lease string, req Request, result Result, rec Disposition) error {
	if err := f.check(ctx, caller, lease); err != nil {
		return err
	}
	now := time.Now().UTC()
	if caller.OwnerProduct != req.OwnerProduct {
		return errors.New("advice owner mismatch")
	}
	if err := req.Validate(now); err != nil {
		return errors.New("advice request invalid")
	}
	if err := result.ValidateFor(req, now); err != nil {
		return errors.New("advice result binding invalid")
	}
	if rec != Recommend(result.Verdict) {
		return errors.New("unsafe advice recommendation")
	}
	// Request and result are transient hash input only, not persisted or logged.
	evidence, err := json.Marshal(struct {
		Request Request
		Result  Result
		Advice  Disposition
	}{req, result, rec})
	if err != nil {
		return errors.New("advice evidence fingerprint failed")
	}
	proof := sha256.Sum256(evidence)
	fp := adviceLeaseFingerprint(caller.OwnerProduct, lease)
	receipt := AdviceReceipt{
		SchemaVersion: SchemaVersion, LeaseFingerprint: fp, EvidenceFingerprint: hex.EncodeToString(proof[:]),
		Verdict: result.Verdict, Recommendation: rec, Engine: result.Engine, EngineVersion: result.EngineVersion,
		ScannedAt: result.ScannedAt.UTC(), RecordedAt: now,
	}
	encoded, err := json.Marshal(receipt)
	if err != nil || len(encoded)+1 > maxAdviceReceiptBytes {
		return errors.New("advice receipt size invalid")
	}
	encoded = append(encoded, byte(10))
	if err := ctx.Err(); err != nil {
		return err
	}
	directory, err := openPrivateJournalDirectory(f.dir)
	if err != nil {
		return errors.New("advice receipt directory unavailable; hold retained")
	}
	defer directory.Close()
	err = createPrivateJournalRecord(directory, f.dir, fp+".advice", encoded)
	if errors.Is(err, os.ErrExist) {
		return ErrAdviceAlreadyRecorded
	}
	if err != nil {
		return errors.New("advice receipt or directory durability uncertain; hold retained")
	}
	return ctx.Err()
}

// ReadReceipt is INTERNAL only: a VerifiedCaller value must come from an
// authenticated trusted owner adapter, never from request metadata. File mode
// and JSON structure are validated, not cryptographic authenticity.
func (f *FileAdviceRecorder) ReadReceipt(ctx context.Context, caller VerifiedCaller, lease string) (AdviceReceipt, error) {
	if err := f.check(ctx, caller, lease); err != nil {
		return AdviceReceipt{}, err
	}
	fp := adviceLeaseFingerprint(caller.OwnerProduct, lease)
	directory, err := openPrivateJournalDirectory(f.dir)
	if err != nil {
		return AdviceReceipt{}, errors.New("advice receipt directory unavailable or unsafe")
	}
	defer directory.Close()
	raw, err := readPrivateJournalRecord(directory, f.dir, fp+".advice", maxAdviceReceiptBytes)
	if err != nil || !bytes.HasSuffix(raw, []byte{10}) {
		return AdviceReceipt{}, errors.New("advice receipt missing, unreadable or incomplete")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var result AdviceReceipt
	if dec.Decode(&result) != nil {
		return AdviceReceipt{}, errors.New("advice receipt invalid JSON")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return AdviceReceipt{}, errors.New("advice receipt trailing data")
	}
	if result.SchemaVersion != SchemaVersion || result.LeaseFingerprint != fp ||
		len(result.EvidenceFingerprint) != 64 || !lowercaseDigest(result.EvidenceFingerprint) ||
		!identifier.MatchString(result.Engine) || !identifier.MatchString(result.EngineVersion) ||
		result.Recommendation != Recommend(result.Verdict) ||
		(result.Verdict != Clean && result.Verdict != Malicious && result.Verdict != Suspicious && result.Verdict != Inconclusive && result.Verdict != ScanError) ||
		result.ScannedAt.IsZero() || result.RecordedAt.IsZero() ||
		result.ScannedAt.After(result.RecordedAt.Add(5*time.Minute)) ||
		result.RecordedAt.After(time.Now().UTC().Add(5*time.Minute)) {
		return AdviceReceipt{}, errors.New("advice receipt metadata invalid")
	}
	if err := ctx.Err(); err != nil {
		return AdviceReceipt{}, err
	}
	return result, nil
}
