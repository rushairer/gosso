package db

import (
	"encoding/json"
	"fmt"
)

// UnmarshalJSONField unmarshals raw JSON bytes into target.
// If data is nil, target is left untouched (callers should initialise defaults beforehand).
// The fieldName parameter is used in the returned error message for diagnostics.
func UnmarshalJSONField(data []byte, target any, fieldName string) error {
	if data == nil {
		return nil
	}
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("unmarshal %s: %w", fieldName, err)
	}
	return nil
}
