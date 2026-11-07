package scan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"sync"
	"time"
)

const maxCredentialBytes = 4096

// VerifiedCaller is derived from a trusted product-owned authenticator.
// Neither an untrusted scan Request nor an HTTP header directly grants this identity.
type VerifiedCaller struct {
	OwnerProduct string
	Subject      string
}

// CallerAuthenticator must verify the inbound credential using an already
// approved identity/authentication system. This package does not store keys,
// mint tokens, or implement a public transport authentication endpoint.
type CallerAuthenticator interface {
	Authenticate(ctx context.Context, credential []byte) (VerifiedCaller, error)
}

// HeldObject is returned ONLY by a trusted file-owning product adapter after
// authorizing the caller and independently confirming that this exact object
// remains inaccessible to ordinary download/export/release routes.
// LeaseID must identify the owner's specific pending object/version; its
// uniqueness, revocation, expiry, and anti-replay policy belong to the owner.
type HeldObject struct {
	OwnerProduct string
	ObjectID     string
	SHA256       string
	SizeBytes    int64
	LeaseID      string
	Pending      bool
	Content      io.ReadCloser
}

// HeldSourceOwner must authorize access to the held source bytes using the
// verified caller, and attest the pending state. It must not take paths,
// URLs or file access decisions from untrusted request metadata.
type HeldSourceOwner interface {
	OpenHeld(ctx context.Context, caller VerifiedCaller, request Request) (HeldObject, error)
}

// MalwareEngine may be the Clamd adapter or a deterministic test double.
type MalwareEngine interface {
	Scan(ctx context.Context, request Request, content io.ReadCloser) (Result, error)
}

// Keep the trusted local ClamAV adapter compatible with the coordinator.
var _ MalwareEngine = Clamd{}

// AdvisoryRecorder records only the scoped result/lease and recommendation.
// It never grants access, releases a file, deletes an object, or mutates holds.
// Its owner-specific implementation must deduplicate request/lease identities.
type AdvisoryRecorder interface {
	RecordAdvice(ctx context.Context, caller VerifiedCaller, leaseID string, request Request, result Result, recommendation Disposition) error
}

// ScanCoordinator is an in-process development handshake, not a deployed API,
// persistent queue, authenticated HTTP server, or file-owner release engine.
type ScanCoordinator struct {
	Auth      CallerAuthenticator
	Source    HeldSourceOwner
	Engine    MalwareEngine
	Record    AdvisoryRecorder
	Admission JobAdmission
	Capacity  *ScanLimiter
	Readiness ScanReadiness
}

// ScanAdvice is a non-authoritative result, not a permission to release.
type ScanAdvice struct {
	LeaseID        string
	Result         Result
	Recommendation Disposition
}

type ownedContent struct {
	io.ReadCloser
	closeOnce sync.Once
	digest    hash.Hash
	readBytes int64
	sawEOF    bool
}

func (r *ownedContent) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if n > 0 {
		_, _ = r.digest.Write(p[:n])
		r.readBytes += int64(n)
	}
	if errors.Is(err, io.EOF) {
		r.sawEOF = true
	}
	return n, err
}

func (r *ownedContent) matches(request Request) bool {
	return r.sawEOF && r.readBytes == request.SizeBytes &&
		hex.EncodeToString(r.digest.Sum(nil)) == request.SHA256
}

func (r *ownedContent) Close() error {
	var err error
	r.closeOnce.Do(func() { err = r.ReadCloser.Close() })
	return err
}

// Process validates the request, authenticates caller identity, opens only an
// owner-attested pending object, scans its exact bytes and records advice.
// Every error leaves the owner-managed pending hold unchanged; even a clean
// result is advisory, never an automatic release.
func (w ScanCoordinator) Process(ctx context.Context, credential []byte, request Request) (ScanAdvice, error) {
	if ctx == nil {
		return ScanAdvice{}, errors.New("scan context required")
	}
	if w.Auth == nil || w.Source == nil || w.Engine == nil || w.Record == nil || w.Admission == nil || w.Capacity == nil || w.Readiness == nil {
		return ScanAdvice{}, errors.New("scan coordinator dependency missing")
	}
	if err := ctx.Err(); err != nil {
		return ScanAdvice{}, err
	}
	if err := request.Validate(time.Now().UTC()); err != nil {
		return ScanAdvice{}, err
	}
	if len(credential) == 0 || len(credential) > maxCredentialBytes {
		return ScanAdvice{}, errors.New("scan caller credentials rejected")
	}
	caller, err := w.Auth.Authenticate(ctx, credential)
	if err != nil {
		// Do not propagate implementation errors that might contain credentials.
		return ScanAdvice{}, errors.New("scan caller authentication failed")
	}
	if !identifier.MatchString(caller.OwnerProduct) || !identifier.MatchString(caller.Subject) ||
		caller.OwnerProduct != request.OwnerProduct {
		return ScanAdvice{}, errors.New("scan caller not authorized for object owner")
	}
	if err := ctx.Err(); err != nil {
		return ScanAdvice{}, err
	}
	// Fail closed when signed, current signature state and loaded daemon
	// database readiness cannot be independently verified.
	if err := w.Readiness.Check(ctx); err != nil {
		return ScanAdvice{}, errors.New("scan signature readiness is unavailable or unverified")
	}
	if err := ctx.Err(); err != nil {
		return ScanAdvice{}, err
	}
	// Fail before asking the source owner to open content if the scanner is
	// already at its configured single-process capacity.
	releaseSlot, err := w.Capacity.Acquire(ctx)
	if err != nil {
		return ScanAdvice{}, err
	}
	defer releaseSlot()
	if err := ctx.Err(); err != nil {
		return ScanAdvice{}, err
	}

	held, err := w.Source.OpenHeld(ctx, caller, request)
	if err != nil {
		// A faulty source adapter may return an open handle alongside an
		// error; never leave it available after rejecting the request.
		if held.Content != nil {
			_ = held.Content.Close()
		}
		return ScanAdvice{}, errors.New("scan source owner rejected access")
	}
	if held.Content == nil {
		return ScanAdvice{}, errors.New("scan source content missing")
	}
	content := &ownedContent{ReadCloser: held.Content, digest: sha256.New()}
	defer content.Close()

	if !held.Pending || !identifier.MatchString(held.LeaseID) ||
		held.OwnerProduct != caller.OwnerProduct || held.ObjectID != request.ObjectID ||
		held.SHA256 != request.SHA256 || held.SizeBytes != request.SizeBytes {
		return ScanAdvice{}, errors.New("scan source is not an exact attested pending object")
	}
	if err := ctx.Err(); err != nil {
		return ScanAdvice{}, err
	}
	// The durable admission marker must be committed before any source bytes
	// reach the scanner. A failed or replayed admission retains the owner hold.
	if err := w.Admission.Reserve(ctx, caller, held, request); err != nil {
		return ScanAdvice{}, err
	}
	result, err := w.Engine.Scan(ctx, request, content)
	if err != nil {
		return ScanAdvice{}, errors.New("scan engine could not produce a valid verdict")
	}
	if err := result.ValidateFor(request, time.Now().UTC()); err != nil {
		return ScanAdvice{}, errors.New("scan engine result failed object binding")
	}
	if !content.matches(request) {
		return ScanAdvice{}, errors.New("scan engine did not consume exact expected source bytes")
	}
	if err := ctx.Err(); err != nil {
		return ScanAdvice{}, err
	}
	recommendation := Recommend(result.Verdict)
	if err := w.Record.RecordAdvice(ctx, caller, held.LeaseID, request, result, recommendation); err != nil {
		return ScanAdvice{}, errors.New("scan advice could not be recorded")
	}
	return ScanAdvice{LeaseID: held.LeaseID, Result: result, Recommendation: recommendation}, nil
}
