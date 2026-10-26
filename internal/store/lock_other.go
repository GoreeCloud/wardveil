//go:build !linux

package store

import "os"

// The initial service is verified only on Linux. Other platforms must not
// silently run without a crash-released cross-process writer lock.
func lockWriter(_ *os.File) error { return ErrPlatform }
