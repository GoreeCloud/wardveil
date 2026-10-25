package core

import (
 "errors"
 "regexp"
 "time"
)

const SchemaVersion = "1"

var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,95}$`)

func ValidIdentifier(value string) bool { return identifier.MatchString(value) }

type EventInput struct {
 SchemaVersion string `json:"schema_version"`
 Source string `json:"source"`
 SourceEventID string `json:"source_event_id"`
 EventType string `json:"event_type"`
 Severity string `json:"severity"`
 AssetID string `json:"asset_id"`
 OccurredAt time.Time `json:"occurred_at"`
}

type Event struct {
 EventInput
 ID string `json:"id"`
 IngestedAt time.Time `json:"ingested_at"`
}

func (e EventInput) Validate(now time.Time) error {
 if e.SchemaVersion != SchemaVersion { return errors.New("unsupported schema_version") }
 if !ValidIdentifier(e.Source) || !ValidIdentifier(e.SourceEventID) || !ValidIdentifier(e.EventType) || !ValidIdentifier(e.AssetID) { return errors.New("invalid source, source_event_id, event_type or asset_id") }
 switch e.Severity { case "info", "low", "medium", "high", "critical": default: return errors.New("invalid severity") }
 if e.OccurredAt.IsZero() || e.OccurredAt.After(now.Add(5*time.Minute)) || e.OccurredAt.Before(now.Add(-365*24*time.Hour)) { return errors.New("occurred_at is outside permitted time window") }
 return nil
}
