package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnmarshalJSONField_NilData(t *testing.T) {
	target := map[string]string{"existing": "value"}
	err := UnmarshalJSONField(nil, &target, "test_field")
	assert.NoError(t, err)
	assert.Equal(t, "value", target["existing"]) // target untouched
}

func TestUnmarshalJSONField_ValidJSON(t *testing.T) {
	var target map[string]string
	data := []byte(`{"key": "value"}`)
	err := UnmarshalJSONField(data, &target, "test_field")
	require.NoError(t, err)
	assert.Equal(t, "value", target["key"])
}

func TestUnmarshalJSONField_InvalidJSON(t *testing.T) {
	var target map[string]string
	data := []byte(`{invalid json}`)
	err := UnmarshalJSONField(data, &target, "test_field")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "test_field")
}

func TestUnmarshalJSONField_EmptyObject(t *testing.T) {
	var target map[string]string
	data := []byte(`{}`)
	err := UnmarshalJSONField(data, &target, "test_field")
	require.NoError(t, err)
	assert.Empty(t, target)
}

func TestUnmarshalJSONField_EmptyArray(t *testing.T) {
	var target []string
	data := []byte(`[]`)
	err := UnmarshalJSONField(data, &target, "test_field")
	require.NoError(t, err)
	assert.Empty(t, target)
}
