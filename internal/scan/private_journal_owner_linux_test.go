//go:build linux

package scan

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// Synthetic stat metadata allows owner-boundary negative tests without
// privileged chown, so normal CI can exercise the reject path.
type differentJournalOwner struct{ os.FileInfo }

func (f differentJournalOwner) Sys() any {
	stat, ok := f.FileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	copy := *stat
	copy.Uid = uint32(os.Geteuid()) + 1
	return &copy
}

func TestPrivateJournalMetadataRequiresCurrentAccountOwner(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "journal")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	dirInfo, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !privateOwnerDirectory(dirInfo) {
		t.Fatal("owner-held 0700 journal directory was refused")
	}
	if privateOwnerDirectory(differentJournalOwner{dirInfo}) {
		t.Fatal("journal directory owned by another local account was accepted")
	}
	path := filepath.Join(dir, "advice")
	if err := os.WriteFile(path, []byte("test-only\n"), 0600); err != nil {
		t.Fatal(err)
	}
	recordInfo, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !privateOwnerRecord(recordInfo) {
		t.Fatal("owner-held 0600 journal record was refused")
	}
	if privateOwnerRecord(differentJournalOwner{recordInfo}) {
		t.Fatal("journal record owned by another local account was accepted")
	}
	if err := os.Link(path, filepath.Join(root, "second-link")); err != nil {
		t.Fatal(err)
	}
	linked, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if privateOwnerRecord(linked) {
		t.Fatal("multiply hardlinked private journal record was accepted")
	}
}
