package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GoreeCloud/wardveil/internal/core"
	"github.com/GoreeCloud/wardveil/internal/store"
)

const ingestToken = "this-is-only-a-synthetic-ingest-test-token-0000"
const readToken = "this-is-only-a-synthetic-read-test-token-00000"

func fixture(t *testing.T) (*store.Store, http.Handler) {
	t.Helper()
	data, err := store.Open(filepath.Join(t.TempDir(), "private"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = data.Close() })
	api, err := New(data, ingestToken, readToken)
	if err != nil {
		t.Fatal(err)
	}
	return data, api.Handler()
}
func request(handler http.Handler, method, path, token string, payload []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, bytes.NewReader(payload))
	if payload != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}
func input() core.EventInput {
	return core.EventInput{SchemaVersion: "1", Source: "identity", SourceEventID: "sample-1", EventType: "auth.anomaly", Severity: "high", AssetID: "asset.1", OccurredAt: time.Now().UTC().Truncate(time.Second)}
}
func TestAuthenticationAndReplay(t *testing.T) {
	_, handler := fixture(t)
	payload, _ := json.Marshal(input())
	if got := request(handler, "POST", "/v1/events", "", payload).Code; got != 401 {
		t.Fatalf("missing auth: %d", got)
	}
	if got := request(handler, "POST", "/v1/events", readToken, payload).Code; got != 403 {
		t.Fatalf("wrong role: %d", got)
	}
	if got := request(handler, "POST", "/v1/events", ingestToken, payload).Code; got != 201 {
		t.Fatalf("first ingest: %d", got)
	}
	if got := request(handler, "POST", "/v1/events", ingestToken, payload).Code; got != 200 {
		t.Fatalf("same replay: %d", got)
	}
	changed := input()
	changed.Severity = "critical"
	conflict, _ := json.Marshal(changed)
	if got := request(handler, "POST", "/v1/events", ingestToken, conflict).Code; got != 409 {
		t.Fatalf("conflicting replay: %d", got)
	}
	if got := request(handler, "GET", "/v1/events", ingestToken, nil).Code; got != 403 {
		t.Fatalf("wrong read role: %d", got)
	}
	w := request(handler, "GET", "/v1/events?limit=1", readToken, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "auth.anomaly") {
		t.Fatalf("read: %d %s", w.Code, w.Body.String())
	}
	if got := request(handler, "GET", "/v1/events?limit=101", readToken, nil).Code; got != 400 {
		t.Fatalf("bad limit: %d", got)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("sensitive responses are cacheable")
	}
}
func TestInputLimits(t *testing.T) {
	_, handler := fixture(t)
	bad := []byte(`{"schema_version":"1","source":"x","source_event_id":"y","event_type":"z","asset_id":"a","severity":"high","occurred_at":"2026-10-25T00:00:00Z","unknown":"field"}`)
	if got := request(handler, "POST", "/v1/events", ingestToken, bad).Code; got != 400 {
		t.Fatalf("unknown field: %d", got)
	}
	if got := request(handler, "POST", "/v1/events", ingestToken, append([]byte(`{"schema_version":"1","source":"x","source_event_id":"y","event_type":"z","severity":"high","asset_id":"`), append(bytes.Repeat([]byte("x"), 4097), []byte(`","occurred_at":"2026-10-25T00:00:00Z"}`)...)...)).Code; got != 413 {
		t.Fatalf("oversize: %d", got)
	}
	e := input()
	e.Source = "../secret"
	encoded, _ := json.Marshal(e)
	if got := request(handler, "POST", "/v1/events", ingestToken, encoded).Code; got != 422 {
		t.Fatalf("invalid identifier: %d", got)
	}
}
func TestPersistencePermissionsAndReopen(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	db, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	first, created, err := db.Add(input())
	if err != nil || !created {
		t.Fatalf("add: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("file permissions %o", info.Mode().Perm())
	}
	reopened, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	records := reopened.List(10)
	if len(records) != 1 || records[0].ID != first.ID {
		t.Fatalf("lost data after restart: %#v", records)
	}
	_, created, err = reopened.Add(input())
	if err != nil || created {
		t.Fatalf("replay on restart: %v created=%v", err, created)
	}
}
func TestTokenValidation(t *testing.T) {
	db, _ := store.Open(filepath.Join(t.TempDir(), "private"))
	defer db.Close()
	if _, err := New(db, "short", "short"); err == nil {
		t.Fatal("weak tokens allowed")
	}
}

func TestUncertainJournalReturnsUnavailable(t *testing.T) {
	data, handler := fixture(t)
	if got := request(handler, "GET", "/healthz", "", nil).Code; got != 200 {
		t.Fatalf("healthy journal: %d", got)
	}
	// Close the backing file to exercise the write-failure path without
	// changing filesystem permissions or relying on platform-specific faults.
	if err := data.Close(); err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(input())
	if got := request(handler, "POST", "/v1/events", ingestToken, payload).Code; got != 503 {
		t.Fatalf("uncertain write response: %d", got)
	}
	if got := request(handler, "GET", "/healthz", "", nil).Code; got != 503 {
		t.Fatalf("unhealthy journal response: %d", got)
	}
	if got := request(handler, "POST", "/v1/events", ingestToken, payload).Code; got != 503 {
		t.Fatalf("second write should remain refused: %d", got)
	}
}
