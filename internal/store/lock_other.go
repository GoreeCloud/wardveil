//go:build !linux

package store

import "os"

// The initial service is verified only on Linux. Other platforms must not
// silently run without a crash-released cross-process writer lock.
func lockWriter(_ *os.File) error { return ErrPlatform }

// A secure journal open is Linux-only until an independently verified
// equivalent O_NOFOLLOW/inode/link-count implementation exists elsewhere.
func openPrivateJournal(_ string) (*os.File, error) { return nil, ErrPlatform }
