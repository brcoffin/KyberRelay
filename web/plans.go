package main

import "time"

// Subscription plans. Billing isn't implemented yet — a user's Plan defaults to
// "free", and a future payment module (e.g. Stripe webhook) flips it to "pro".
// Feature gates just read these limits, so adding billing later changes no
// enforcement code.

type Plan struct {
	Name         string
	Label        string
	MaxFileBytes int64         // largest single file the sender may transfer
	TTL          time.Duration // how long a delivered file is retained
}

// Limits are per-transfer size and undownloaded-retention. Files are deleted as
// soon as the recipient downloads them (burn-after-download), so retention only
// bounds how long an unretrieved file lingers.
var plans = map[string]Plan{
	"free": {Name: "free", Label: "Free", MaxFileBytes: 2 << 30, TTL: 7 * 24 * time.Hour},
	"pro":  {Name: "pro", Label: "Pro", MaxFileBytes: 100 << 30, TTL: 30 * 24 * time.Hour},
	"team": {Name: "team", Label: "Team", MaxFileBytes: 250 << 30, TTL: 30 * 24 * time.Hour},
}

// planFor returns the plan for a name, defaulting to free for unknown/empty.
func planFor(name string) Plan {
	if p, ok := plans[name]; ok {
		return p
	}
	return plans["free"]
}
