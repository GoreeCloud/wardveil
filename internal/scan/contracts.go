// Package scan defines advisory, provider-neutral malware scanning contracts.
// It does not open files, run engines, quarantine files, or authorize release.
package scan

import (
	"encoding/hex"
	"errors"
	"regexp"
	"time"
)

const SchemaVersion = "1"

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,95}$`)

type Verdict string

const (
	Clean        Verdict = "clean"
	Malicious    Verdict = "malicious"
	Suspicious   Verdict = "suspicious"
	Inconclusive Verdict = "inconclusive"
	ScanError    Verdict = "error"
)

// Request carries a metadata-only reference to an object still controlled
// by its owning product. It never grants direct access to an arbitrary path.
type Request struct {
	SchemaVersion string    `json:"schema_version"`
	RequestID     string    `json:"request_id"`
	OwnerProduct  string    `json:"owner_product"`
	ObjectID      string    `json:"object_id"`
	SHA256        string    `json:"sha256"`
	SizeBytes     int64     `json:"size_bytes"`
	RequestedAt   time.Time `json:"requested_at"`
}

func (r Request) Validate(now time.Time) error {
	if r.SchemaVersion != SchemaVersion {
		return errors.New("unsupported scan request schema")
	}
	if !identifier.MatchString(r.RequestID) || !identifier.MatchString(r.OwnerProduct) || !identifier.MatchString(r.ObjectID) {
		return errors.New("invalid scan request identifier")
	}
	if len(r.SHA256) != 64 {
		return errors.New("sha256 must be a lowercase 64-character hex digest")
	}
	if _, err := hex.DecodeString(r.SHA256); err != nil || !lowercaseDigest(r.SHA256) {
		return errors.New("sha256 must be a lowercase 64-character hex digest")
	}
	// Metadata is accepted up to 1 TiB; workers may impose stricter limits.
	if r.SizeBytes < 0 || r.SizeBytes > 1<<40 {
		return errors.New("size_bytes outside metadata bounds")
	}
	if r.RequestedAt.IsZero() || r.RequestedAt.After(now.Add(5*time.Minute)) || r.RequestedAt.Before(now.Add(-24*time.Hour)) {
		return errors.New("requested_at outside allowed intake window")
	}
	return nil
}

func lowercaseDigest(s string) bool {
	for _, ch := range s {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
}

// Result is a non-authoritative scan verdict. The owning product retains
// all authority to change visibility, quarantine, or retention state.
type Result struct {
	SchemaVersion string    `json:"schema_version"`
	RequestID     string    `json:"request_id"`
	OwnerProduct  string    `json:"owner_product"`
	ObjectID      string    `json:"object_id"`
	SHA256        string    `json:"sha256"`
	Verdict       Verdict   `json:"verdict"`
	Engine        string    `json:"engine"`
	EngineVersion string    `json:"engine_version"`
	SignatureID   string    `json:"signature_id,omitempty"`
	ScannedAt     time.Time `json:"scanned_at"`
}

// ValidateFor matches a verdict to the exact object and request; an unrelated
// result must not be used to release a different object.
func (r Result) ValidateFor(request Request, now time.Time) error {
	if r.SchemaVersion != SchemaVersion || request.SchemaVersion != SchemaVersion {
		return errors.New("unsupported scan result schema")
	}
	if r.RequestID != request.RequestID || r.OwnerProduct != request.OwnerProduct ||
		r.ObjectID != request.ObjectID || r.SHA256 != request.SHA256 {
		return errors.New("scan result does not match original request")
	}
	if !identifier.MatchString(r.Engine) || !identifier.MatchString(r.EngineVersion) {
		return errors.New("invalid engine identification")
	}
	if r.SignatureID != "" && !identifier.MatchString(r.SignatureID) {
		return errors.New("invalid signature identifier")
	}
	switch r.Verdict {
	case Clean, Malicious, Suspicious, Inconclusive, ScanError:
	default:
		return errors.New("unsupported scan verdict")
	}
	if r.ScannedAt.IsZero() || r.ScannedAt.Before(request.RequestedAt.Add(-5*time.Minute)) || r.ScannedAt.After(now.Add(5*time.Minute)) {
		return errors.New("scanned_at outside permissible result window")
	}
	return nil
}

type Disposition string

const (
	// EligibleForOwnerReview is NOT permission to make an object public.
	EligibleForOwnerReview Disposition = "eligible_for_owner_review"
	RetainPendingReview    Disposition = "retain_pending_review"
)

// Recommend is advisory only. All non-clean or unknown outcomes recommend
// retaining the source object's pre-release hold until owner-controlled review.
func Recommend(verdict Verdict) Disposition {
	if verdict == Clean {
		return EligibleForOwnerReview
	}
	return RetainPendingReview
}
