package utility

import (
	"sync/atomic"
	"time"
)

// dummyWorkDuration stores the sleep duration for DummyWork.
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

// DummyWork performs a sleep-based timing padding to equalise the response time
// of early-return paths with the real authentication path. This mitigates timing
// side-channel attacks that could distinguish "email not found" from "wrong
// password" based on latency differences.
//
// Previous bcrypt-based implementation burned ~100ms of CPU per call, which
// enabled CPU exhaustion under distributed brute-force from many source IPs.
// Sleep achieves the same timing protection at zero CPU cost.
//
// The duration is configurable via SetDummyWorkDuration to match varying
// Argon2id parameter configurations.
func DummyWork() {
	time.Sleep(time.Duration(dummyWorkDuration.Load()))
}
