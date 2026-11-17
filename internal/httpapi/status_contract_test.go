package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/GoreeCloud/wardveil/internal/store"
)

const statusToken = "this-is-only-a-synthetic-status-scope-token-0000"

func statusFixture(t *testing.T) (*store.Store, http.Handler) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "status-private"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	server, err := NewWithStatus(db, ingestToken, readToken, statusToken)
	if err != nil {
		t.Fatal(err)
	}
	return db, server.Handler()
}

func TestStatusContractDisabledByDefault(t *testing.T) {
	_, legacy := fixture(t)
	for _, token := range []string{"", statusToken, readToken} {
		if got := request(legacy, "GET", "/v1/status", token, nil).Code; got != http.StatusNotFound {
			t.Fatalf("disabled status route unexpectedly available: %d", got)
		}
	}
}

func TestStatusContractAuthenticationAndLeastPrivilege(t *testing.T) {
	db, handler := statusFixture(t)
	for _, tc := range []struct {
		name  string
		token string
		want  int
	}{
		{"missing", "", 401}, {"wrong", "something-else", 403},
		{"event-read", readToken, 403}, {"event-ingest", ingestToken, 403},
		{"status", statusToken, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := request(handler, "GET", "/v1/status", tc.token, nil)
			if resp.Code != tc.want {
				t.Fatalf("unexpected status: %d instead of %d", resp.Code, tc.want)
			}
			if resp.Header().Get("Cache-Control") != "no-store" ||
				resp.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("status response must not be cached or sniffed")
			}
			if resp.Code != 200 && len(db.List(10)) != 0 {
				t.Fatal("unauthorized requests persisted events")
			}
		})
	}
	// This status-only bearer must never grant event listing or ingestion.
	for _, method := range []string{"GET", "POST"} {
		resp := request(handler, method, "/v1/events", statusToken, nil)
		if resp.Code != http.StatusForbidden {
			t.Fatalf("status token crossed event %s scope: %d", method, resp.Code)
		}
	}
}

func TestStatusContractExactVersionedSourceProjection(t *testing.T) {
	_, handler := statusFixture(t)
	resp := request(handler, "GET", "/v1/status", statusToken, nil)
	if resp.Code != http.StatusOK || resp.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatalf("unexpected status or response content type: %d", resp.Code)
	}
	var payload map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload) != 3 || payload["schema_version"] != "wardveil.status.v1" || payload["state"] != "ok" {
		t.Fatalf("invalid versioned fields: %v", payload)
	}
	observedAt, ok := payload["observed_at"].(string)
	if !ok || !regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[.][0-9]{3}Z$`).MatchString(observedAt) {
		t.Fatal("timestamp must come from the UTC server as canonical millisecond timestamp")
	}
	observedTime, err := time.Parse(time.RFC3339Nano, observedAt)
	if err != nil || time.Since(observedTime) > 5*time.Second || time.Until(observedTime) > 5*time.Second {
		t.Fatal("source observation time invalid or stale")
	}
}

func TestStatusContractRejectsAmbiguousRequests(t *testing.T) {
	_, handler := statusFixture(t)
	for _, path := range []string{"/v1/status?all", "/v1/status?", "/v1/status?limit=1"} {
		if got := request(handler, "GET", path, statusToken, nil).Code; got != 400 {
			t.Fatalf("query accepted: %s status=%d", path, got)
		}
	}
	if got := request(handler, "POST", "/v1/status", statusToken, nil).Code; got != 405 {
		t.Fatalf("non-read method accepted: %d", got)
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/v1/status", nil)
	r.Header.Add("Authorization", "Bearer "+statusToken)
	r.Header.Add("Authorization", "Bearer "+readToken)
	handler.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("ambiguous bearer header accepted: %d", w.Code)
	}
	payload := []byte(`{"private":"not accepted"}`)
	if got := request(handler, "GET", "/v1/status", statusToken, payload).Code; got != 400 {
		t.Fatalf("body-bearing status request accepted: %d", got)
	}
}

func TestStatusContractRejectsWeakOrOverlappingCredentials(t *testing.T) {
	db, _ := statusFixture(t)
	for _, token := range []string{"too-short", readToken, ingestToken, string(make([]byte, 1025))} {
		if _, err := NewWithStatus(db, ingestToken, readToken, token); err == nil {
			t.Fatal("invalid status secret accepted")
		}
	}
	if _, err := NewWithStatus(nil, ingestToken, readToken, statusToken); err == nil {
		t.Fatal("nil store accepted")
	}
}

func TestStatusContractJournalFailureIsSourceObservedDegraded(t *testing.T) {
	db, handler := statusFixture(t)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	_, _, err := db.Add(input())
	if err == nil {
		t.Fatal("expected journal write failure")
	}
	resp := request(handler, "GET", "/v1/status", statusToken, nil)
	if resp.Code != 503 {
		t.Fatalf("journal-unwritable response: %d", resp.Code)
	}
	var payload map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload) != 3 || payload["state"] != "degraded" || payload["schema_version"] != "wardveil.status.v1" {
		t.Fatalf("unexpected degraded contract: %v", payload)
	}
}
