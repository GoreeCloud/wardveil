//go:build linux

package scan

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestCoordinatorDurableAdmissionPreventsReplayAndLeaks(t *testing.T) {
	payload := []byte("privately held bytes")
	req := coordinatorRequest(payload)
	journal, err := OpenFileAdmission(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	var scans, records, closes atomic.Int64
	worker := ScanCoordinator{
		Auth: coordinatorAuth(),
		Source: sourceOwnerFunc(func(_ context.Context, _ VerifiedCaller, _ Request) (HeldObject, error) {
			source := io.NopCloser(bytes.NewReader(payload))
			return coordinatorHeld(req, countedClose{ReadCloser: source, onClose: func() { closes.Add(1) }}), nil
		}),
		Engine: malwareEngineFunc(func(_ context.Context, actual Request, src io.ReadCloser) (Result, error) {
			scans.Add(1)
			if _, err := io.Copy(io.Discard, src); err != nil {
				return Result{}, err
			}
			return coordinatorResult(actual, Clean), nil
		}),
		Record: recordFunc(func(context.Context, VerifiedCaller, string, Request, Result, Disposition) error {
			records.Add(1)
			return nil
		}),
		Admission: journal,
		Capacity:  testScanLimiter(),
	}
	if _, err := worker.Process(context.Background(), []byte("authorized-fixture"), req); err != nil {
		t.Fatalf("first scan failed: %v", err)
	}
	result, err := worker.Process(context.Background(), []byte("authorized-fixture"), req)
	if !errors.Is(err, ErrAdmissionReplay) || result != (ScanAdvice{}) {
		t.Fatalf("replay accepted: %+v %v", result, err)
	}
	if scans.Load() != 1 || records.Load() != 1 || closes.Load() != 2 {
		t.Fatalf("replay effects: scans=%d records=%d closes=%d", scans.Load(), records.Load(), closes.Load())
	}
}

type countedClose struct {
	io.ReadCloser
	onClose func()
}

func (c countedClose) Close() error {
	c.onClose()
	return c.ReadCloser.Close()
}

func TestCoordinatorCapacityDenialBeforeOpeningOwner(t *testing.T) {
	req := coordinatorRequest([]byte("fixture"))
	limit, err := NewScanLimiter(1)
	if err != nil {
		t.Fatal(err)
	}
	release, err := limit.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	var opened atomic.Int64
	w := ScanCoordinator{
		Auth: coordinatorAuth(),
		Source: sourceOwnerFunc(func(context.Context, VerifiedCaller, Request) (HeldObject, error) {
			opened.Add(1)
			t.Fatal("source opened despite capacity being full")
			return HeldObject{}, nil
		}),
		Engine: malwareEngineFunc(func(context.Context, Request, io.ReadCloser) (Result, error) {
			t.Fatal("engine ran despite capacity being full")
			return Result{}, nil
		}),
		Record: recordFunc(func(context.Context, VerifiedCaller, string, Request, Result, Disposition) error {
			t.Fatal("result recorded despite capacity being full")
			return nil
		}),
		Admission: admissionFunc(func(context.Context, VerifiedCaller, HeldObject, Request) error {
			t.Fatal("admission reserved despite capacity being full")
			return nil
		}),
		Capacity: limit,
	}
	out, err := w.Process(context.Background(), []byte("authorized-fixture"), req)
	if !errors.Is(err, ErrScanBusy) || out != (ScanAdvice{}) || opened.Load() != 0 {
		t.Fatalf("capacity fail-open: %+v %v", out, err)
	}
}

func TestFileAdmissionErrorStaysPendingWithMarker(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "journal")
	store, err := OpenFileAdmission(dir)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("fixture")
	req := coordinatorRequest(payload)
	var scans atomic.Int32
	w := ScanCoordinator{
		Auth: coordinatorAuth(),
		Source: sourceOwnerFunc(func(context.Context, VerifiedCaller, Request) (HeldObject, error) {
			return coordinatorHeld(req, io.NopCloser(bytes.NewReader(payload))), nil
		}),
		Engine: malwareEngineFunc(func(_ context.Context, actual Request, source io.ReadCloser) (Result, error) {
			scans.Add(1)
			if _, err := io.Copy(io.Discard, source); err != nil {
				return Result{}, err
			}
			return coordinatorResult(actual, Clean), nil
		}),
		Record: recordFunc(func(context.Context, VerifiedCaller, string, Request, Result, Disposition) error {
			return errors.New("durable recorder offline")
		}),
		Admission: store,
		Capacity:  testScanLimiter(),
	}
	out, err := w.Process(context.Background(), []byte("authorized-fixture"), req)
	if err == nil || out != (ScanAdvice{}) {
		t.Fatal("advice returned with failed recording")
	}
	out, err = w.Process(context.Background(), []byte("authorized-fixture"), req)
	if !errors.Is(err, ErrAdmissionReplay) || out != (ScanAdvice{}) || scans.Load() != 1 {
		t.Fatalf("replay after uncertain record was permitted: %+v %v scans=%d", out, err, scans.Load())
	}
}
