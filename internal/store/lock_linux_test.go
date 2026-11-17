package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestExclusiveWriterAndRelease(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	first, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := Open(dir); !errors.Is(err, ErrLocked) {
		if second != nil {
			second.Close()
		}
		first.Close()
		t.Fatalf("concurrent writer was not rejected: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatalf("lock not released after close: %v", err)
	}
	defer reopened.Close()
}

func TestJournalOpenRejectsHardLinkedOutsideFile(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "external-events.jsonl")
	if err := os.WriteFile(outside, []byte{}, 0600); err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(private, "events.jsonl")); err != nil {
		t.Fatal(err)
	}
	st, err := Open(private)
	if err == nil {
		_ = st.Close()
		t.Fatal("outside hardlinked event journal was accepted as private")
	}
}
