package scan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

var (
	ErrAdmissionReplay = errors.New("scan owner lease already admitted")
	ErrScanBusy        = errors.New("scan capacity is exhausted")
)

// JobAdmission atomically reserves an owner-generated pending-object lease
// before any bytes reach a malware engine. A trusted implementation must
// survive process restarts, share state among all workers, and fail closed
// on uncertain writes. Admission never releases or publishes an object.
type JobAdmission interface {
	Reserve(ctx context.Context, caller VerifiedCaller, held HeldObject, request Request) error
}

// FileAdmission is a minimal Linux/local-filesystem replay guard intended for
// development and an isolated single-host scanner. Each successful admission
// creates a private, fsynced O_EXCL marker keyed by product + owner lease.
// Markers are never automatically deleted; owner-authorized rescans require
// a new pending lease. The configured directory must be trusted, private,
// persistent, and on a filesystem that honors atomic O_EXCL and fsync.
// This is not a distributed job queue, owner lease verifier, or audit store.
type FileAdmission struct {
	dir string
}

// OpenFileAdmission validates a private (0700) directory or creates one.
// The path is trusted configuration, never a value from an upload/request.
func OpenFileAdmission(dir string) (*FileAdmission, error) {
	if !filepath.IsAbs(dir) {
		return nil, errors.New("admission directory must be absolute")
	}
	created := false
	if err := os.Mkdir(dir, 0700); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("admission directory: %w", err)
		}
	} else {
		created = true
	}
	if err := checkPrivateAdmissionDirectory(dir); err != nil {
		return nil, err
	}
	if created {
		// Persist a newly created directory's entry before relying on
		// durable admission markers inside it.
		parent, err := os.Open(filepath.Dir(dir))
		if err != nil {
			return nil, fmt.Errorf("admission parent directory unavailable: %w", err)
		}
		syncErr := parent.Sync()
		closeErr := parent.Close()
		if syncErr != nil || closeErr != nil {
			return nil, errors.New("admission parent directory durability uncertain")
		}
	}
	return &FileAdmission{dir: dir}, nil
}

// Open and validate an actual private directory without following its final
// path component. A subsequent journal operation also pins a descriptor.
func checkPrivateAdmissionDirectory(path string) error {
	dir, err := openPrivateJournalDirectory(path)
	if err != nil {
		return err
	}
	return dir.Close()
}

// Reserve durably marks a lease before it can be scanned. Existing markers,
// including incomplete markers left by a crash, reject re-use. An I/O error
// never counts as admitted. The marker may remain after an ambiguous error,
// intentionally preferring operator recovery over unsafe automatic retry.
func (f *FileAdmission) Reserve(ctx context.Context, caller VerifiedCaller, held HeldObject, req Request) error {
	if ctx == nil {
		return errors.New("missing admission context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if f == nil || f.dir == "" {
		return errors.New("unconfigured admission journal")
	}
	directory, err := openPrivateJournalDirectory(f.dir)
	if err != nil {
		return fmt.Errorf("admission directory became unsafe: %w", err)
	}
	defer directory.Close()
	if !identifier.MatchString(caller.OwnerProduct) || caller.OwnerProduct != req.OwnerProduct ||
		!identifier.MatchString(caller.Subject) || !identifier.MatchString(held.LeaseID) ||
		!held.Pending || held.OwnerProduct != req.OwnerProduct || held.ObjectID != req.ObjectID ||
		held.SHA256 != req.SHA256 || held.SizeBytes != req.SizeBytes {
		return errors.New("invalid admission ownership or held-object binding")
	}
	// A zero byte separates owner and lease, avoiding ambiguous composite IDs.
	h := sha256.Sum256([]byte(caller.OwnerProduct + "\x00" + held.LeaseID))
	name := hex.EncodeToString(h[:]) + ".admitted"
	// A pinned verified directory descriptor eliminates path re-resolution
	// between the permission check, O_EXCL create, and directory fsync.
	// Write no user bytes, credentials, object names or unhashed lease IDs.
	err = createPrivateJournalRecord(directory, f.dir, name, []byte("wardveil-scan-admitted-v1\n"))
	if errors.Is(err, os.ErrExist) {
		return ErrAdmissionReplay
	}
	if err != nil {
		return errors.New("admission marker or directory durability uncertain; retain hold")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

// ScanLimiter prevents unbounded in-flight scans in a single coordinator.
// Admission across multiple processes additionally needs an external shared
// capacity service. A full limiter rejects immediately (no unbounded queue).
type ScanLimiter struct {
	slots chan struct{}
}

func NewScanLimiter(maxConcurrent int) (*ScanLimiter, error) {
	if maxConcurrent < 1 || maxConcurrent > 32 {
		return nil, errors.New("scan concurrency must be between 1 and 32")
	}
	return &ScanLimiter{slots: make(chan struct{}, maxConcurrent)}, nil
}

func (l *ScanLimiter) Acquire(ctx context.Context) (func(), error) {
	if ctx == nil {
		return nil, errors.New("missing scan capacity context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if l == nil || l.slots == nil {
		return nil, errors.New("scan capacity limiter required")
	}
	select {
	case l.slots <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-l.slots }) }, nil
	default:
		return nil, ErrScanBusy
	}
}
