package store

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// flock is held for the lifetime of the open file description and released
// automatically on close or process exit, including unexpected termination.
func lockWriter(file *os.File) error {
	for {
		err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, syscall.EINTR):
			continue
		case errors.Is(err, syscall.EWOULDBLOCK):
			return ErrLocked
		default:
			return fmt.Errorf("lock event journal: %w", err)
		}
	}
}
