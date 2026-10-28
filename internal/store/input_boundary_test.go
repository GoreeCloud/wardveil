package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/GoreeCloud/wardveil/internal/core"
)

func TestDirectStoreRejectsInvalidEventWithoutBreakingRecovery(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	valid := core.EventInput{
		SchemaVersion: core.SchemaVersion,
		Source:        "fixture",
		SourceEventID: "event-1",
		EventType:     "test.event",
		Severity:      "info",
		AssetID:       "asset-1",
		OccurredAt:    time.Now().UTC(),
	}
	invalid := valid
	invalid.SchemaVersion = "unknown"
	if _, created, err := s.Add(invalid); created || !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid direct append: created=%v err=%v", created, err)
	}
	if !s.Writable() {
		t.Fatal("input rejection must not poison a healthy journal")
	}
	if _, created, err := s.Add(valid); !created || err != nil {
		t.Fatalf("valid append after input rejection: created=%v err=%v", created, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatalf("persisted journal failed to recover: %v", err)
	}
	defer reopened.Close()
	if got := reopened.List(10); len(got) != 1 || got[0].SourceEventID != valid.SourceEventID {
		t.Fatalf("unexpected recovered records: %#v", got)
	}
	for _, limit := range []int{0, -1, -100} {
		if got := reopened.List(limit); len(got) != 0 {
			t.Fatalf("limit %d returned %d events", limit, len(got))
		}
	}
}
