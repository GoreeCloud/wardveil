package httpapi

import (
    "crypto/sha256"
    "crypto/subtle"
    "errors"
    "net/http"
    "sort"
    "strings"

    "github.com/GoreeCloud/wardveil/internal/core"
)

// sourceCredential binds a hashed development credential to one producer.
// This is not a production token management or rotation service.
type sourceCredential struct {
    source string
    hash   [32]byte
}

func configureCredentials(tokens map[string]string, readToken string) ([]sourceCredential, [32]byte, error) {
    var zero [32]byte
    if len(tokens) == 0 || len(tokens) > 64 {
        return nil, zero, errors.New("configure 1 to 64 named event sources")
    }
    if len(readToken) < 32 || len(readToken) > 1024 {
        return nil, zero, errors.New("read token must be 32 to 1024 bytes")
    }
    readHash := sha256.Sum256([]byte(readToken))
    used := make(map[[32]byte]bool, len(tokens))
    credentials := make([]sourceCredential, 0, len(tokens))
    for source, token := range tokens {
        if !core.ValidIdentifier(source) {
            return nil, zero, errors.New("invalid configured source identifier")
        }
        if len(token) < 32 || len(token) > 1024 {
            return nil, zero, errors.New("each source token must be 32 to 1024 bytes")
        }
        digest := sha256.Sum256([]byte(token))
        if digest == readHash || used[digest] {
            return nil, zero, errors.New("source and read credentials must be unique")
        }
        used[digest] = true
        credentials = append(credentials, sourceCredential{source: source, hash: digest})
    }
    sort.Slice(credentials, func(i, j int) bool { return credentials[i].source < credentials[j].source })
    return credentials, readHash, nil
}

func tokenFromRequest(r *http.Request) (string, bool) {
    if len(r.Header.Values("Authorization")) != 1 {
        return "", false
    }
    parts := strings.Fields(r.Header.Get("Authorization"))
    returnToken := ""
    if len(parts) == 2 && parts[0] == "Bearer" && len(parts[1]) >= 32 && len(parts[1]) <= 1024 {
        returnToken = parts[1]
    }
    return returnToken, returnToken != ""
}

func (s *Server) authenticateSource(w http.ResponseWriter, r *http.Request) (string, bool) {
    token, ok := tokenFromRequest(r)
    if !ok {
        problem(w, http.StatusUnauthorized, "bearer token required")
        return "", false
    }
    digest := sha256.Sum256([]byte(token))
    var source string
    for _, credential := range s.sources {
        if subtle.ConstantTimeCompare(digest[:], credential.hash[:]) == 1 {
            source = credential.source
        }
    }
    if source == "" {
        problem(w, http.StatusForbidden, "access denied")
        return "", false
    }
    return source, true
}
