package scan

import (
	"errors"
	"io"
	"testing"
)

// A faulty Unix socket writer must never be treated as having sent a complete
// scanner frame just because it returned nil error with fewer bytes written.
type partialNilWriter struct {
	calls   int
	shorten int
}

func (w *partialNilWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls == w.shorten && len(p) > 0 {
		return len(p) - 1, nil
	}
	return len(p), nil
}
func TestClamdChunkFramingRejectsShortWrites(t *testing.T) {
	for _, tc := range []struct {
		name    string
		shorten int
	}{
		{"short_header", 1}, {"short_payload", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := &partialNilWriter{shorten: tc.shorten}
			if err := writeChunk(w, []byte("synthetic scan bytes")); !errors.Is(err, io.ErrShortWrite) {
				t.Fatalf("partial scanner write accepted: %v", err)
			}
		})
	}
}
