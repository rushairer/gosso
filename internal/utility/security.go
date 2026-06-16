package utility

import "golang.org/x/crypto/bcrypt"

// DummyWork performs a bcrypt hash to pad the response time of early-return
// paths. This mitigates timing side-channel attacks that could distinguish
// different outcomes based on response latency (e.g., "email not found" vs
// "email found" or "cooldown active" vs "fresh request").
// bcrypt at DefaultCost (~100ms) overlaps with the DB + Redis + SMTP overhead
// on the real path, making the two indistinguishable.
func DummyWork() {
	_, _ = bcrypt.GenerateFromPassword([]byte("dummy-work-padding"), bcrypt.DefaultCost)
}
