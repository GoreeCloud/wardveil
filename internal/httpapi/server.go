package httpapi

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/GoreeCloud/wardveil/internal/core"
	"github.com/GoreeCloud/wardveil/internal/store"
)

type Server struct {
	store         *store.Store
	ingestHash    [32]byte
	readHash      [32]byte
	statusHash    [32]byte
	statusEnabled bool
}

// New preserves the legacy two-scope API with no status route.
func New(data *store.Store, ingestToken, readToken string) (*Server, error) {
	return NewWithStatus(data, ingestToken, readToken, "")
}

// NewWithStatus opts a development instance into a separate, status-only scope.
// It never gives a status reader event-read or event-ingest permissions.
// An empty status token leaves the route unregistered (HTTP 404).
func NewWithStatus(data *store.Store, ingestToken, readToken, statusToken string) (*Server, error) {
	if data == nil || len(ingestToken) < 32 || len(readToken) < 32 || ingestToken == readToken {
		return nil, errors.New("distinct ingest and read tokens of at least 32 bytes are required")
	}
	if statusToken != "" && (len(statusToken) < 32 || len(statusToken) > 1024 ||
		statusToken == ingestToken || statusToken == readToken) {
		return nil, errors.New("status token must be distinct and 32..1024 bytes")
	}
	server := &Server{
		store:      data,
		ingestHash: sha256.Sum256([]byte(ingestToken)),
		readHash:   sha256.Sum256([]byte(readToken)),
	}
	if statusToken != "" {
		server.statusHash = sha256.Sum256([]byte(statusToken))
		server.statusEnabled = true
	}
	return server, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	if s.statusEnabled {
		mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
			// Authorize before returning any journal-writability signal.
			if !s.authorize(w, r, s.statusHash) {
				return
			}
			if r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength > 0 || len(r.TransferEncoding) != 0 {
				problem(w, http.StatusBadRequest, "status request must not contain query or body")
				return
			}
			// Fixed, source-owned wire contract. No event content or actor identity.
			state := "ok"
			code := http.StatusOK
			if !s.store.Writable() {
				state = "degraded"
				code = http.StatusServiceUnavailable
			}
			send(w, code, struct {
				SchemaVersion string `json:"schema_version"`
				State         string `json:"state"`
				ObservedAt    string `json:"observed_at"`
			}{
				SchemaVersion: "wardveil.status.v1",
				State:         state,
				ObservedAt:    time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
			})
		})
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if !s.store.Writable() {
			problem(w, http.StatusServiceUnavailable, "event ingestion unavailable")
			return
		}
		send(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /v1/events", func(w http.ResponseWriter, r *http.Request) {
		if !s.authorize(w, r, s.ingestHash) {
			return
		}
		mediatype, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediatype != "application/json" {
			problem(w, http.StatusUnsupportedMediaType, "application/json required")
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
		if err != nil {
			decodeError(w, err)
			return
		}
		if duplicateEventKeys(raw) {
			problem(w, http.StatusBadRequest, "duplicate or invalid JSON event fields")
			return
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		var input core.EventInput
		if err := dec.Decode(&input); err != nil {
			decodeError(w, err)
			return
		}
		var extra any
		if err := dec.Decode(&extra); err != io.EOF {
			// The decoder may discover a body limit while checking for
			// trailing JSON or whitespace. Preserve the 413 classification.
			var max *http.MaxBytesError
			if errors.As(err, &max) {
				problem(w, http.StatusRequestEntityTooLarge, "request too large")
			} else {
				problem(w, http.StatusBadRequest, "one JSON object required")
			}
			return
		}
		if err := input.Validate(time.Now().UTC()); err != nil {
			problem(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		event, created, err := s.store.Add(input)
		if err != nil {
			if errors.Is(err, store.ErrUncertain) {
				problem(w, http.StatusServiceUnavailable, "event journal requires operator recovery")
				return
			}
			if errors.Is(err, store.ErrConflict) {
				problem(w, http.StatusConflict, "conflicting source event")
				return
			}
			if errors.Is(err, store.ErrFull) {
				problem(w, http.StatusInsufficientStorage, "development event capacity reached")
				return
			}
			problem(w, http.StatusInternalServerError, "event could not be saved")
			return
		}
		status := http.StatusOK
		if created {
			status = http.StatusCreated
		}
		send(w, status, map[string]any{"event": event, "created": created})
	})
	mux.HandleFunc("GET /v1/events", func(w http.ResponseWriter, r *http.Request) {
		if !s.authorize(w, r, s.readHash) {
			return
		}
		for k := range r.URL.Query() {
			if k != "limit" {
				problem(w, http.StatusBadRequest, "unknown query parameter")
				return
			}
		}
		limit := 25
		if values, ok := r.URL.Query()["limit"]; ok {
			if len(values) != 1 {
				problem(w, http.StatusBadRequest, "invalid limit")
				return
			}
			value, err := strconv.Atoi(values[0])
			if err != nil || value < 1 || value > 100 {
				problem(w, http.StatusBadRequest, "limit must be 1..100")
				return
			}
			limit = value
		}
		send(w, http.StatusOK, map[string]any{"events": s.store.List(limit)})
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(w, r)
	})
}

// duplicateEventKeys rejects ambiguous fields before decoding into EventInput.
// EventInput is intentionally flat; nested values are rejected separately by
// the typed decoder. JSON names are case-folded by encoding/json, so the check
// must also reject case variants that could overwrite the same struct field.
func duplicateEventKeys(raw []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(raw))
	start, err := dec.Token()
	if err != nil || start != json.Delim('{') {
		return true
	}
	seen := make(map[string]struct{})
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return true
		}
		key, ok := token.(string)
		if !ok {
			return true
		}
		folded := strings.ToLower(key)
		if _, exists := seen[folded]; exists {
			return true
		}
		seen[folded] = struct{}{}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return true
		}
	}
	end, err := dec.Token()
	return err != nil || end != json.Delim('}')
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request, expected [32]byte) bool {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		problem(w, http.StatusUnauthorized, "bearer token required")
		return false
	}
	parts := strings.Fields(values[0])
	if len(parts) != 2 || parts[0] != "Bearer" || len(parts[1]) > 1024 {
		problem(w, http.StatusUnauthorized, "bearer token required")
		return false
	}
	actual := sha256.Sum256([]byte(parts[1]))
	if subtle.ConstantTimeCompare(actual[:], expected[:]) != 1 {
		problem(w, http.StatusForbidden, "access denied")
		return false
	}
	return true
}

func decodeError(w http.ResponseWriter, err error) {
	var max *http.MaxBytesError
	if errors.As(err, &max) {
		problem(w, http.StatusRequestEntityTooLarge, "request too large")
		return
	}
	problem(w, http.StatusBadRequest, "invalid JSON event")
}
func problem(w http.ResponseWriter, status int, message string) {
	send(w, status, map[string]string{"error": message})
}
func send(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
