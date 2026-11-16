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

// openPrivateJournal checks the opened inode, not only a pathname inspected
// before open. The final O_NOFOLLOW also prevents a symlink substitution.
// A second hard link can expose journal data or accept writes outside the
// private directory, even with mode 0600.
func openPrivateJournal(name string) (*os.File, error) {
	file, err := os.OpenFile(name, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || stat.Nlink != 1 {
		file.Close()
		return nil, errors.New("journal file must be a private, singly linked regular file (0600)")
	}
	return file, nil
}
