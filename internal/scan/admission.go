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

// Always revalidate permissions before reserve, not just at construction.
// The containing path remains trusted administrator configuration.
func checkPrivateAdmissionDirectory(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() || fi.Mode().Perm()&0077 != 0 {
		return errors.New("admission directory must be a private 0700 directory, not a symlink")
	}
	return nil
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
	if err := checkPrivateAdmissionDirectory(f.dir); err != nil {
		return fmt.Errorf("admission directory became unsafe: %w", err)
	}
	if !identifier.MatchString(caller.OwnerProduct) || caller.OwnerProduct != req.OwnerProduct ||
		!identifier.MatchString(caller.Subject) || !identifier.MatchString(held.LeaseID) ||
		!held.Pending || held.OwnerProduct != req.OwnerProduct || held.ObjectID != req.ObjectID ||
		held.SHA256 != req.SHA256 || held.SizeBytes != req.SizeBytes {
		return errors.New("invalid admission ownership or held-object binding")
	}
	// A zero byte separates owner and lease, avoiding ambiguous composite IDs.
	h := sha256.Sum256([]byte(caller.OwnerProduct + "\x00" + held.LeaseID))
	name := filepath.Join(f.dir, hex.EncodeToString(h[:])+".admitted")
	fd, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		return ErrAdmissionReplay
	}
	if err != nil {
		return fmt.Errorf("admission marker create failed: %w", err)
	}
	// Write no user bytes, credentials, object names or unhashed lease IDs.
	_, writeErr := fd.WriteString("wardveil-scan-admitted-v1\n")
	if writeErr == nil {
		writeErr = fd.Sync()
	}
	closeErr := fd.Close()
	if writeErr != nil || closeErr != nil {
		return errors.New("admission marker durability uncertain; retain hold")
	}
	dirFd, err := os.Open(f.dir)
	if err != nil {
		return errors.New("admission directory sync unavailable; retain hold")
	}
	syncErr := dirFd.Sync()
	closeErr = dirFd.Close()
	if syncErr != nil || closeErr != nil {
		return errors.New("admission directory durability uncertain; retain hold")
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
