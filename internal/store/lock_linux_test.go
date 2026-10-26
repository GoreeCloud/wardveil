package store

import (
	"errors"
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
