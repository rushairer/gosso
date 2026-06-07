package utility

import "encoding/json"

// MustMarshalJSON marshals v to JSON, returning nil on error.
// Intended for best-effort serialization (e.g., audit metadata).
func MustMarshalJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage("{}")
	}
	return json.RawMessage(b)
}
