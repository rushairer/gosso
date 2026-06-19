package utility

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDummyWorkWithContext_SleepsForDuration(t *testing.T) {
	// Set a known duration
	require.NoError(t, SetDummyWorkDuration(50*time.Millisecond))
	defer func() { _ = SetDummyWorkDuration(100 * time.Millisecond) }() // restore default

	start := time.Now()
	DummyWorkWithContext(context.Background())
	elapsed := time.Since(start)

	assert.GreaterOrEqual(t, elapsed, 45*time.Millisecond, "should sleep for at least the configured duration")
}

func TestDummyWorkWithContext_CancelsOnContextDone(t *testing.T) {
	require.NoError(t, SetDummyWorkDuration(5*time.Second)) // long duration
	defer func() { _ = SetDummyWorkDuration(100 * time.Millisecond) }()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	start := time.Now()
	DummyWorkWithContext(ctx)
	elapsed := time.Since(start)

	assert.Less(t, elapsed, 500*time.Millisecond, "should return quickly when context is cancelled")
}

func TestSetDummyWorkDuration_ReturnsErrorOnZero(t *testing.T) {
	err := SetDummyWorkDuration(0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be positive")
}

func TestSetDummyWorkDuration_ReturnsErrorOnNegative(t *testing.T) {
	err := SetDummyWorkDuration(-1 * time.Second)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be positive")
}
