package utility

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDummyWorkWithContext_SleepsForDuration(t *testing.T) {
	// Set a known duration
	SetDummyWorkDuration(50 * time.Millisecond)
	defer SetDummyWorkDuration(100 * time.Millisecond) // restore default

	start := time.Now()
	DummyWorkWithContext(context.Background())
	elapsed := time.Since(start)

	assert.GreaterOrEqual(t, elapsed, 45*time.Millisecond, "should sleep for at least the configured duration")
}

func TestDummyWorkWithContext_CancelsOnContextDone(t *testing.T) {
	SetDummyWorkDuration(5 * time.Second) // long duration
	defer SetDummyWorkDuration(100 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	start := time.Now()
	DummyWorkWithContext(ctx)
	elapsed := time.Since(start)

	assert.Less(t, elapsed, 500*time.Millisecond, "should return quickly when context is cancelled")
}

func TestSetDummyWorkDuration_PanicsOnZero(t *testing.T) {
	assert.Panics(t, func() {
		SetDummyWorkDuration(0)
	})
}

func TestSetDummyWorkDuration_PanicsOnNegative(t *testing.T) {
	assert.Panics(t, func() {
		SetDummyWorkDuration(-1 * time.Second)
	})
}
