package utility

import (
	"context"
	"sync/atomic"
	"time"
)

// dummyWorkDuration stores the sleep duration for DummyWorkWithContext.
// Defaults to 100ms to match typical Argon2id computation time.
var dummyWorkDuration atomic.Int64

func init() {
	dummyWorkDuration.Store(int64(100 * time.Millisecond))
}

// SetDummyWorkDuration overrides the default DummyWork sleep duration.
// Must be called before any authentication operations. Panics if d <= 0.
func SetDummyWorkDuration(d time.Duration) {
	if d <= 0 {
		panic("dummy work duration must be positive")
	}
	dummyWorkDuration.Store(int64(d))
}

// DummyWorkWithContext performs sleep-based timing padding to equalise the response
// time of early-return paths with the real authentication path. This mitigates timing
// side-channel attacks that could distinguish "email not found" from "wrong password"
// based on latency differences.
//
// The context allows cancellation during server shutdown, preventing goroutine
// accumulation when the server is stopping. If the context is cancelled before the
// duration elapses, the function returns immediately.
func DummyWorkWithContext(ctx context.Context) {
	duration := time.Duration(dummyWorkDuration.Load())
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
}
