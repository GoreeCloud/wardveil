package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/GoreeCloud/wardveil/internal/core"
)

func TestWriteFailureIsFailClosed(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "private"))
	if err != nil {
		t.Fatal(err)
	}
	// Simulate an I/O failure after opening the journal. The first failed
	// acknowledgement must poison the writer instead of allowing a later
	// append to follow an unknown on-disk state.
	if err := s.file.Close(); err != nil {
		t.Fatal(err)
	}
	input := core.EventInput{
		SchemaVersion: core.SchemaVersion,
		Source:        "fixture",
		SourceEventID: "event-1",
		EventType:     "test.event",
		Severity:      "info",
		AssetID:       "asset-1",
		OccurredAt:    time.Now().UTC(),
	}
	if _, created, err := s.Add(input); created || !errors.Is(err, ErrUncertain) {
		t.Fatalf("first failure = created %v, error %v", created, err)
	}
	if s.Writable() {
		t.Fatal("failed journal still marked writable")
	}
	if _, created, err := s.Add(input); created || !errors.Is(err, ErrUncertain) {
		t.Fatalf("subsequent write = created %v, error %v", created, err)
	}
	if got := s.List(10); len(got) != 0 {
		t.Fatalf("unacknowledged event became visible: %#v", got)
	}
}

func TestFullJournalIsNotReportedWritable(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "private"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if !s.Writable() {
		t.Fatal("empty journal should accept an append")
	}
	// Model the documented in-memory record bound without 10,000 fsyncs.
	s.records = make([]core.Event, maxEvents)
	if s.Writable() {
		t.Fatal("capacity-exhausted journal reported writable")
	}
	if _, created, err := s.Add(core.EventInput{Source: "fixture", SourceEventID: "new"}); created || !errors.Is(err, ErrFull) {
		t.Fatalf("full journal append = created %v, error %v", created, err)
	}
}
