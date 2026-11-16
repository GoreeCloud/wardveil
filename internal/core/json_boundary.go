package core

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"unicode"
)

// canonicalJSONField is the Unicode simple-fold key used by encoding/json
// when matching object names to exported Go struct fields. A map avoids
// pairwise comparisons against many untrusted journal keys.
func canonicalJSONField(key string) string {
	return strings.Map(func(r rune) rune {
		minimum := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < minimum {
				minimum = next
			}
		}
		return minimum
	}, key)
}

// HasAmbiguousFlatJSONKeys rejects malformed/duplicate fields before typed
// decoding an Event or EventInput. Both have intentionally flat JSON records.
// It checks semantic Unicode-folded aliases, including escaped spellings.
// Callers must separately validate the decoded schema and values.
func HasAmbiguousFlatJSONKeys(raw []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return true
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		name, err := decoder.Token()
		if err != nil {
			return true
		}
		key, ok := name.(string)
		if !ok {
			return true
		}
		normalized := canonicalJSONField(key)
		if _, duplicate := seen[normalized]; duplicate {
			return true
		}
		seen[normalized] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return true
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return true
	}
	// These APIs accept exactly one JSON object, not a concatenated stream.
	_, err = decoder.Token()
	return err != io.EOF
}
