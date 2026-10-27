package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

func TestOpenRejectsCorruptPersistedEventContracts(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	base := core.Event{
		EventInput: core.EventInput{
			SchemaVersion: core.SchemaVersion,
			Source: "fixture",
			SourceEventID: "event-1",
			EventType: "auth.anomaly",
			Severity: "high",
			AssetID: "asset-1",
			OccurredAt: now,
		},
		ID: strings.Repeat("a", 32),
		IngestedAt: now,
	}
	cases := []struct {
		name string
		mutate func(*core.Event)
	}{
		{"unsupported schema", func(e *core.Event) { e.SchemaVersion = "2" }},
		{"invalid severity", func(e *core.Event) { e.Severity = "unrecognized" }},
		{"invalid source", func(e *core.Event) { e.Source = "../other-tenant" }},
		{"unrecognized event ID", func(e *core.Event) { e.ID = strings.Repeat("z", 32) }},
		{"impossible event time", func(e *core.Event) { e.OccurredAt = e.IngestedAt.Add(-366 * 24 * time.Hour) }},
		{"future ingestion", func(e *core.Event) { e.IngestedAt = now.Add(time.Hour) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			event := base
			tc.mutate(&event)
			encoded, err := json.Marshal(event)
			if err != nil { t.Fatal(err) }
			dir := filepath.Join(t.TempDir(), "private")
			if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
			if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), append(encoded, '\n'), 0600); err != nil { t.Fatal(err) }
			loaded, err := Open(dir)
			if err == nil {
				_ = loaded.Close()
				t.Fatal("invalid persisted event was accepted")
			}
		})
	}
	t.Run("unexpected record field", func(t *testing.T) {
		encoded, err := json.Marshal(base)
		if err != nil { t.Fatal(err) }
		untrusted := strings.TrimSuffix(string(encoded), "}") + `,"unexpected":"sensitive"}` + "\n"
		dir := filepath.Join(t.TempDir(), "private")
		if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
		if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(untrusted), 0600); err != nil { t.Fatal(err) }
		loaded, err := Open(dir)
		if err == nil {
			_ = loaded.Close()
			t.Fatal("unrecognized persisted event field was accepted")
		}
	})
}
