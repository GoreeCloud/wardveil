//go:build linux

package scan

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPinnedPrivateJournalRejectsDirectoryReplacement(t *testing.T) {
	root := t.TempDir()
	original := filepath.Join(root, "private")
	if err := os.Mkdir(original, 0700); err != nil {
		t.Fatal(err)
	}
	dir, err := openPrivateJournalDirectory(original)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	elsewhere := filepath.Join(root, "attacker-private")
	if err := os.Mkdir(elsewhere, 0700); err != nil {
		t.Fatal(err)
	}
	renamed := filepath.Join(root, "renamed-private")
	if err := os.Rename(original, renamed); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, original); err != nil {
		t.Fatal(err)
	}
	if err := createPrivateJournalRecord(dir, original, "lease.admitted", []byte("test-only\n")); err == nil {
		t.Fatal("renamed original dir accepted as current safe destination")
	}
	if _, err := readPrivateJournalRecord(dir, original, "lease.admitted", 1536); err == nil {
		t.Fatal("read accepted from replaced directory")
	}
	for _, path := range []string{filepath.Join(elsewhere, "lease.admitted"), filepath.Join(renamed, "lease.admitted")} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("journal wrote unexpected file after directory replacement: %s, err=%v", path, err)
		}
	}
}

func TestPinnedPrivateJournalRejectsSymlinkRecordsAndTraversal(t *testing.T) {
	root := t.TempDir()
	private := filepath.Join(root, "private")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	dir, err := openPrivateJournalDirectory(private)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	outside := filepath.Join(root, "private-outside-record")
	if err := os.WriteFile(outside, []byte("should stay private outside\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(private, "shadow.advice")); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateJournalRecord(dir, private, "shadow.advice", 1536); err == nil {
		t.Fatal("symlink target followed by private receipt reader")
	}
	if err := createPrivateJournalRecord(dir, private, "shadow.advice", []byte("must not write\n")); !errors.Is(err, os.ErrExist) {
		t.Fatalf("existing symlink record not rejected: %v", err)
	}
	for _, name := range []string{"../private-outside-record", "/etc/passwd", "", ".", "..", "dir/file", "dir\\file"} {
		if err := createPrivateJournalRecord(dir, private, name, []byte("bad\n")); err == nil {
			t.Fatalf("unsafe basename accepted: %q", name)
		}
		if _, err := readPrivateJournalRecord(dir, private, name, 1536); err == nil {
			t.Fatalf("unsafe read basename accepted: %q", name)
		}
	}
	actual, err := os.ReadFile(outside)
	if err != nil || !bytes.Equal(actual, []byte("should stay private outside\n")) {
		t.Fatal("unsafe symlink target was mutated")
	}
}

func TestPinnedPrivateJournalCommitAndReadback(t *testing.T) {
	root := t.TempDir()
	private := filepath.Join(root, "private")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	dir, err := openPrivateJournalDirectory(private)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	data := []byte("synthetic receipt\n")
	if err := createPrivateJournalRecord(dir, private, "one.advice", data); err != nil {
		t.Fatal(err)
	}
	got, err := readPrivateJournalRecord(dir, private, "one.advice", 1536)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("pinned journal read mismatch: %q err=%v", got, err)
	}
	if err := createPrivateJournalRecord(dir, private, "one.advice", data); !errors.Is(err, syscall.EEXIST) {
		t.Fatalf("duplicate pinned record allowed: %v", err)
	}
	if err := os.Chmod(private, 0755); err != nil {
		t.Fatal(err)
	}
	if err := createPrivateJournalRecord(dir, private, "two.advice", data); err == nil {
		t.Fatal("permission drift accepted on descriptor")
	}
	if _, err := readPrivateJournalRecord(dir, private, "one.advice", 1536); err == nil {
		t.Fatal("permission drift accepted by pinned record reader")
	}
}

func TestPinnedPrivateJournalRejectsHardlinkedRecord(t *testing.T) {
	root := t.TempDir()
	private := filepath.Join(root, "private")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	dir, err := openPrivateJournalDirectory(private)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	if err := createPrivateJournalRecord(dir, private, "record.advice", []byte("synthetic receipt\n")); err != nil {
		t.Fatal(err)
	}
	outsideLink := filepath.Join(root, "external-link")
	if err := os.Link(filepath.Join(private, "record.advice"), outsideLink); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateJournalRecord(dir, private, "record.advice", 1536); err == nil {
		t.Fatal("hard-linked journal record accepted")
	}
}
