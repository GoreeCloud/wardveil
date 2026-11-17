//go:build !linux

package scan

import (
	"errors"
	"os"
)

// The private journal uses Linux openat(O_NOFOLLOW) and directory fsync.
// Refuse weaker implicit portability rather than silently dropping controls.
var errPrivateJournalPlatform = errors.New("private scan journals require Linux secure directory operations")

func openPrivateJournalDirectory(string) (*os.File, error) {
	return nil, errPrivateJournalPlatform
}
func verifyPrivateJournalDirectory(*os.File, string) error {
	return errPrivateJournalPlatform
}
func createPrivateJournalRecord(*os.File, string, string, []byte) error {
	return errPrivateJournalPlatform
}
func readPrivateJournalRecord(*os.File, string, string, int64) ([]byte, error) {
	return nil, errPrivateJournalPlatform
}
