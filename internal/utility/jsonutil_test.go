package utility

import (
	"encoding/json"
	"testing"
)

func TestMarshalJSONOrEmpty(t *testing.T) {
	t.Run("normal object", func(t *testing.T) {
		result := MarshalJSONOrEmpty(map[string]any{"key": "value"})
		if string(result) != `{"key":"value"}` {
			t.Errorf("got %s, want {\"key\":\"value\"}", string(result))
		}
	})

	t.Run("nil value", func(t *testing.T) {
		result := MarshalJSONOrEmpty(nil)
		if string(result) != "null" {
			t.Errorf("got %s, want null", string(result))
		}
	})

	t.Run("unmarshalable value returns empty object", func(t *testing.T) {
		result := MarshalJSONOrEmpty(make(chan int))
		if string(result) != "{}" {
			t.Errorf("got %s, want {}", string(result))
		}
	})

	t.Run("nested object", func(t *testing.T) {
		result := MarshalJSONOrEmpty(map[string]any{"nested": map[string]int{"a": 1}})
		var m map[string]any
		if err := json.Unmarshal(result, &m); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if m["nested"] == nil {
			t.Error("expected nested key")
		}
	})
}
