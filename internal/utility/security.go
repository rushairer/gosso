package utility

import "time"

// DummyWork performs a sleep-based timing padding to equalise the response time
// of early-return paths with the real authentication path. This mitigates timing
// side-channel attacks that could distinguish "email not found" from "wrong
// password" based on latency differences.
//
// Previous bcrypt-based implementation burned ~100ms of CPU per call, which
// enabled CPU exhaustion under distributed brute-force from many source IPs.
// Sleep achieves the same timing protection at zero CPU cost.
func DummyWork() {
	time.Sleep(100 * time.Millisecond)
}
