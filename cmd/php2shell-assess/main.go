// Command php2shell-assess reads a bounded, explicitly supplied synthetic or
// authorized inventory from stdin. It does not access hosts or make requests.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/GoreeCloud/wardveil/internal/advisory"
)

const maxInventoryBytes = 64 * 1024
const maxInventoryRecords = 128

func readInventory(reader io.Reader) ([]advisory.PHPRuntime, error) {
	input, err := io.ReadAll(io.LimitReader(reader, maxInventoryBytes+1))
	if err != nil || len(input) > maxInventoryBytes {
		return nil, errors.New("invalid inventory size")
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('[') {
		return nil, errors.New("expected a JSON array")
	}
	var records []advisory.PHPRuntime
	for decoder.More() {
		if len(records) >= maxInventoryRecords {
			return nil, errors.New("too many inventory records")
		}
		start, err := decoder.Token()
		if err != nil || start != json.Delim('{') {
			return nil, errors.New("expected a JSON inventory record")
		}
		seen := make(map[string]bool, 2)
		var record advisory.PHPRuntime
		for decoder.More() {
			keyValue, err := decoder.Token()
			if err != nil {
				return nil, errors.New("invalid inventory field")
			}
			key, ok := keyValue.(string)
			if !ok || seen[key] || (key != "version" && key != "role") {
				return nil, errors.New("duplicate or unsupported inventory field")
			}
			seen[key] = true
			value, err := decoder.Token()
			if err != nil {
				return nil, errors.New("invalid inventory value")
			}
			text, ok := value.(string)
			if !ok {
				return nil, errors.New("inventory fields must be strings")
			}
			if key == "version" {
				record.Version = text
			} else {
				record.Role = text
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') || !seen["version"] || !seen["role"] {
			return nil, errors.New("incomplete inventory record")
		}
		records = append(records, record)
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim(']') || len(records) == 0 {
		return nil, errors.New("invalid or empty inventory")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("unexpected data after inventory")
	}
	return records, nil
}

func run(in io.Reader, out io.Writer) error {
	records, err := readInventory(in)
	if err != nil {
		return err
	}
	assessments := make([]advisory.PHPAssessment, 0, len(records))
	for i, record := range records {
		assessments = append(assessments, advisory.PHP2ShellAssessment(record, i))
	}
	return json.NewEncoder(out).Encode(struct {
		SchemaVersion string                   `json:"schema_version"`
		Scope         string                   `json:"scope"`
		Assessments   []advisory.PHPAssessment `json:"assessments"`
	}{
		SchemaVersion: "wardveil.php2shell.advisory.v1",
		Scope:         "offline_non_authoritative_no_host_verification",
		Assessments:   assessments,
	})
}

func main() {
	if err := run(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "invalid bounded inventory or output unavailable")
		os.Exit(2)
	}
}
