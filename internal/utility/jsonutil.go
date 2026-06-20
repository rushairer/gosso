package utility

import "encoding/json"

// MarshalJSONOrEmpty marshals v to JSON, returning {} on error.
// Intended for best-effort serialization (e.g., audit metadata).
func MarshalJSONOrEmpty(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage("{}")
	}
	return json.RawMessage(b)
}
