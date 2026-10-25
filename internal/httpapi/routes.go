package httpapi

import (
 "crypto/sha256"
 "crypto/subtle"
 "encoding/json"
 "errors"
 "io"
 "mime"
 "net/http"
 "strconv"
 "time"

 "github.com/GoreeCloud/wardveil/internal/core"
 "github.com/GoreeCloud/wardveil/internal/store"
)

func (s *Server) Handler() http.Handler {
 mux := http.NewServeMux()
 mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
  send(w, http.StatusOK, map[string]string{"status":"ok"})
 })
 mux.HandleFunc("POST /v1/events", func(w http.ResponseWriter, r *http.Request) {
  source, ok := s.authenticateSource(w, r)
  if !ok { return }
  mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
  if err != nil || mediaType != "application/json" {
   problem(w, http.StatusUnsupportedMediaType, "application/json required"); return
  }
  r.Body = http.MaxBytesReader(w, r.Body, 4096)
  dec := json.NewDecoder(r.Body)
  dec.DisallowUnknownFields()
  var input core.EventInput
  if err := dec.Decode(&input); err != nil { decodeError(w, err); return }
  var extra any
  if err := dec.Decode(&extra); err != io.EOF {
   problem(w, http.StatusBadRequest, "one JSON object required"); return
  }
  if err := input.Validate(time.Now().UTC()); err != nil {
   problem(w, http.StatusUnprocessableEntity, err.Error()); return
  }
  if input.Source != source {
   problem(w, http.StatusForbidden, "access denied"); return
  }
  event, created, err := s.store.Add(input)
  if err != nil {
   if errors.Is(err, store.ErrConflict) { problem(w, http.StatusConflict, "conflicting source event"); return }
   if errors.Is(err, store.ErrFull) { problem(w, http.StatusInsufficientStorage, "development event capacity reached"); return }
   problem(w, http.StatusInternalServerError, "event could not be saved"); return
  }
  status := http.StatusOK
  if created { status = http.StatusCreated }
  send(w, status, map[string]any{"event":event, "created":created})
 })
 mux.HandleFunc("GET /v1/events", func(w http.ResponseWriter, r *http.Request) {
  if !s.authorizeRead(w, r) { return }
  for k := range r.URL.Query() {
   if k != "limit" { problem(w, http.StatusBadRequest, "unknown query parameter"); return }
  }
  limit := 25
  if values, ok := r.URL.Query()["limit"]; ok {
   if len(values) != 1 { problem(w, http.StatusBadRequest, "invalid limit"); return }
   value, err := strconv.Atoi(values[0])
   if err != nil || value < 1 || value > 100 {
    problem(w, http.StatusBadRequest, "limit must be 1..100"); return
   }
   limit = value
  }
  send(w, http.StatusOK, map[string]any{"events":s.store.List(limit)})
 })
 return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
  w.Header().Set("Cache-Control", "no-store")
  w.Header().Set("X-Content-Type-Options", "nosniff")
  mux.ServeHTTP(w, r)
 })
}

func (s *Server) authorizeRead(w http.ResponseWriter, r *http.Request) bool {
 token, ok := tokenFromRequest(r)
 if !ok { problem(w, http.StatusUnauthorized, "bearer token required"); return false }
 hash := sha256.Sum256([]byte(token))
 if subtle.ConstantTimeCompare(hash[:],s.readHash[:]) != 1 {
  problem(w, http.StatusForbidden, "access denied"); return false
 }
 return true
}

func decodeError(w http.ResponseWriter, err error) {
 var tooBig *http.MaxBytesError
 if errors.As(err, &tooBig) { problem(w, http.StatusRequestEntityTooLarge, "request too large"); return }
 problem(w, http.StatusBadRequest, "invalid JSON event")
}
func problem(w http.ResponseWriter, status int, message string) {
 send(w,status,map[string]string{"error":message})
}
func send(w http.ResponseWriter, status int, value any) {
 w.Header().Set("Content-Type","application/json; charset=utf-8")
 w.WriteHeader(status)
 _ = json.NewEncoder(w).Encode(value)
}
