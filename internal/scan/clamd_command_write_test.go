package scan

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

type clamdShortWriter struct {
	take    int
	err     error
	written bytes.Buffer
}

func (w *clamdShortWriter) Write(p []byte) (int, error) {
	n := w.take
	if n > len(p) {
		n = len(p)
	}
	if n < 0 {
		n = 0
	}
	_, _ = w.written.Write(p[:n])
	return n, w.err
}

// The version and stream command headers are integrity-critical: a writer
// returning an incomplete command with nil error must not be accepted.
func TestClamdCommandRejectsShortAndFailedWrites(t *testing.T) {
	for _, command := range []string{"zVERSION\x00", "zINSTREAM\x00"} {
		t.Run(command, func(t *testing.T) {
			for _, count := range []int{0, 1, len(command) - 1} {
				writer := &clamdShortWriter{take: count}
				if err := writeClamdCommand(writer, command); !errors.Is(err, io.ErrShortWrite) {
					t.Errorf("accepted incomplete command bytes %d/%d: %v", count, len(command), err)
				}
			}
			failure := errors.New("forced write failure")
			w := &clamdShortWriter{take: len(command), err: failure}
			if err := writeClamdCommand(w, command); !errors.Is(err, failure) {
				t.Errorf("ignored writer error: %v", err)
			}
			w = &clamdShortWriter{take: len(command)}
			if err := writeClamdCommand(w, command); err != nil || w.written.String() != command {
				t.Errorf("valid command failed: %v", err)
			}
		})
	}
}
