package store

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/GoreeCloud/wardveil/internal/core"
)

var (
	ErrConflict  = errors.New("source event id already used with different content")
	ErrFull      = errors.New("event capacity reached")
	ErrUncertain = errors.New("event journal write outcome uncertain; operator recovery required")
)

const maxEvents = 10000

type Store struct {
	mu        sync.Mutex
	file      *os.File
	records   []core.Event
	byKey     map[string]int
	uncertain bool
}

func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("data directory must be private (0700) and not a symlink")
	}
	name := filepath.Join(dir, "events.jsonl")
	if info, err := os.Lstat(name); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return nil, errors.New("event file must be private regular file (0600)")
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	file, err := os.OpenFile(name, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	s := &Store{file: file, byKey: make(map[string]int)}
	if err := s.load(); err != nil {
		file.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	stat, err := s.file.Stat()
	if err != nil {
		return err
	}
	if stat.Size() > 8*1024*1024 {
		return errors.New("event store exceeds development size limit")
	}
	if stat.Size() > 0 {
		last := []byte{0}
		if _, err := s.file.ReadAt(last, stat.Size()-1); err != nil {
			return err
		}
		if last[0] != '\n' {
			return errors.New("event store has incomplete final record")
		}
	}
	if _, err := s.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	scan := bufio.NewScanner(s.file)
	scan.Buffer(make([]byte, 4096), 8192)
	for scan.Scan() {
		if len(s.records) >= maxEvents {
			return ErrFull
		}
		var event core.Event
		if err := json.Unmarshal(scan.Bytes(), &event); err != nil {
			return fmt.Errorf("corrupt event record: %w", err)
		}
		if event.ID == "" || event.Source == "" || event.SourceEventID == "" || event.IngestedAt.IsZero() {
			return errors.New("invalid persisted event record")
		}
		key := event.Source + "\x00" + event.SourceEventID
		if _, exists := s.byKey[key]; exists {
			return errors.New("duplicate persisted source event")
		}
		s.byKey[key] = len(s.records)
		s.records = append(s.records, event)
	}
	if err := scan.Err(); err != nil {
		return err
	}
	_, err = s.file.Seek(0, io.SeekEnd)
	return err
}

func (s *Store) Close() error { s.mu.Lock(); defer s.mu.Unlock(); return s.file.Close() }

// Writable reports whether this process can still acknowledge new journal writes.
// An unsuccessful write or sync may have reached disk; do not accept more events
// until an operator has inspected and reopened the journal.
func (s *Store) Writable() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.uncertain
}

func (s *Store) Add(input core.EventInput) (core.Event, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.uncertain {
		return core.Event{}, false, ErrUncertain
	}
	key := input.Source + "\x00" + input.SourceEventID
	if i, ok := s.byKey[key]; ok {
		existing := s.records[i]
		if existing.EventInput != input {
			return core.Event{}, false, ErrConflict
		}
		return existing, false, nil
	}
	if len(s.records) >= maxEvents {
		return core.Event{}, false, ErrFull
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return core.Event{}, false, err
	}
	event := core.Event{EventInput: input, ID: hex.EncodeToString(b), IngestedAt: time.Now().UTC()}
	line, err := json.Marshal(event)
	if err != nil {
		return core.Event{}, false, err
	}
	line = append(line, '\n')
	if n, err := s.file.Write(line); err != nil || n != len(line) {
		s.uncertain = true
		if err == nil {
			err = io.ErrShortWrite
		}
		return core.Event{}, false, fmt.Errorf("%w: %v", ErrUncertain, err)
	}
	if err := s.file.Sync(); err != nil {
		s.uncertain = true
		return core.Event{}, false, fmt.Errorf("%w: %v", ErrUncertain, err)
	}
	s.byKey[key] = len(s.records)
	s.records = append(s.records, event)
	return event, true, nil
}

func (s *Store) List(limit int) []core.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit > len(s.records) {
		limit = len(s.records)
	}
	out := make([]core.Event, 0, limit)
	for i := len(s.records) - 1; i >= len(s.records)-limit; i-- {
		out = append(out, s.records[i])
	}
	return out
}
