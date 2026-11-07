//go:build linux

package scan

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// openPrivateJournalDirectory obtains a directory file descriptor without
// following the final component. Journal operations must use this descriptor,
// not re-resolve a pathname after the privacy check.
func openPrivateJournalDirectory(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || strings.IndexByte(path, 0) >= 0 {
		return nil, errors.New("private journal directory must be a trusted absolute path")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), path)
	if err := verifyPrivateJournalDirectory(dir, path); err != nil {
		_ = dir.Close()
		return nil, err
	}
	return dir, nil
}

// verifyPrivateJournalDirectory catches permission drift, symlink replacement
// and a different inode at the configured path. Parent components remain
// trusted administrator configuration, not untrusted request-controlled input.
func verifyPrivateJournalDirectory(dir *os.File, path string) error {
	if dir == nil {
		return errors.New("private journal directory handle missing")
	}
	actual, err := dir.Stat()
	if err != nil || !actual.IsDir() || actual.Mode().Perm()&0077 != 0 {
		return errors.New("private journal directory descriptor unsafe")
	}
	named, err := os.Lstat(path)
	if err != nil || !named.IsDir() || named.Mode().Perm()&0077 != 0 ||
		!os.SameFile(actual, named) {
		return errors.New("private journal directory path changed or became unsafe")
	}
	return nil
}

func safeJournalFilename(name string) bool {
	return name != "" && name != "." && name != ".." &&
		!strings.ContainsAny(name, "/\\") && strings.IndexByte(name, 0) < 0
}

// createPrivateJournalRecord anchors O_EXCL to the already-verified directory
// descriptor. Existing files and uncertain fsyncs fail closed. No cleanup or
// automatic retry is attempted for a failed or interrupted record.
func createPrivateJournalRecord(dir *os.File, configuredPath, name string, content []byte) error {
	if !safeJournalFilename(name) || len(content) == 0 {
		return errors.New("invalid private journal record")
	}
	if err := verifyPrivateJournalDirectory(dir, configuredPath); err != nil {
		return err
	}
	fd, err := syscall.Openat(int(dir.Fd()), name,
		syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	record := os.NewFile(uintptr(fd), name)
	n, writeErr := record.Write(content)
	if writeErr == nil && n != len(content) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = record.Sync()
	}
	closeErr := record.Close()
	if writeErr != nil || closeErr != nil {
		return errors.New("private journal record durability uncertain")
	}
	if err := dir.Sync(); err != nil {
		return errors.New("private journal directory sync uncertain")
	}
	if err := verifyPrivateJournalDirectory(dir, configuredPath); err != nil {
		return errors.New("private journal directory changed during commit")
	}
	return nil
}

// readPrivateJournalRecord uses openat(O_NOFOLLOW) and fstat on the opened
// file. This prevents a symlink swap between Lstat and path-based ReadFile.
// A hostile writer with access to the trusted directory still requires
// broader filesystem isolation and cryptographic tamper-evidence.
func readPrivateJournalRecord(dir *os.File, configuredPath, name string, maxBytes int64) ([]byte, error) {
	if !safeJournalFilename(name) || maxBytes < 1 {
		return nil, errors.New("invalid private journal read")
	}
	if err := verifyPrivateJournalDirectory(dir, configuredPath); err != nil {
		return nil, err
	}
	fd, err := syscall.Openat(int(dir.Fd()), name,
		syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	record := os.NewFile(uintptr(fd), name)
	defer record.Close()
	info, err := record.Stat()
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode().Perm()&0077 != 0 || info.Size() < 2 || info.Size() > maxBytes {
		return nil, errors.New("private journal record file unsafe")
	}
	// Do not read files linked into the private journal from outside it.
	// A valid, create-exclusive journal record is never hard-linked.
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Nlink != 1 {
		return nil, errors.New("private journal record has unexpected hard links")
	}
	content, err := io.ReadAll(io.LimitReader(record, maxBytes+1))
	if err != nil || int64(len(content)) != info.Size() {
		return nil, errors.New("private journal record incomplete or changed")
	}
	after, err := record.Stat()
	if err != nil || !os.SameFile(info, after) || after.Size() != info.Size() ||
		!after.Mode().IsRegular() || after.Mode().Perm()&0077 != 0 {
		return nil, errors.New("private journal record changed during read")
	}
	if err := verifyPrivateJournalDirectory(dir, configuredPath); err != nil {
		return nil, err
	}
	return content, nil
}
