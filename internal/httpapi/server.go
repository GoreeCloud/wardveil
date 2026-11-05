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
	store      *store.Store
	ingestHash [32]byte
	readHash   [32]byte
}

func New(data *store.Store, ingestToken, readToken string) (*Server, error) {
	if len(ingestToken) < 32 || len(readToken) < 32 || ingestToken == readToken {
		return nil, errors.New("distinct ingest and read tokens of at least 32 bytes are required")
	}
	return &Server{store: data, ingestHash: sha256.Sum256([]byte(ingestToken)), readHash: sha256.Sum256([]byte(readToken))}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
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
	parts := strings.Fields(r.Header.Get("Authorization"))
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
