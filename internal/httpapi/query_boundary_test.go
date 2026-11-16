package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestEventReadRejectsMalformedQueryBeforeReturningEvents(t *testing.T) {
	_, handler := fixture(t)
	encoded, err := json.Marshal(input())
	if err != nil {
		t.Fatal(err)
	}
	if got := request(handler, http.MethodPost, "/v1/events", ingestToken, encoded).Code; got != http.StatusCreated {
		t.Fatalf("test fixture ingest: %d", got)
	}
	for _, rawQuery := range []string{
		"limit=%GG",
		"limit=1&ignored=%GG",
		"limit=1;ignored=anything",
	} {
		t.Run(rawQuery, func(t *testing.T) {
			got := request(handler, http.MethodGet, "/v1/events?"+rawQuery, readToken, nil)
			if got.Code != http.StatusBadRequest {
				t.Errorf("malformed query got HTTP %d, want 400", got.Code)
			}
			if strings.Contains(got.Body.String(), "auth.anomaly") {
				t.Fatal("malformed query exposed event payload")
			}
		})
	}
	if got := request(handler, http.MethodGet, "/v1/events?limit=1", readToken, nil).Code; got != http.StatusOK {
		t.Fatalf("valid read query rejected: HTTP %d", got)
	}
}
