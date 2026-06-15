package main

import (
	"sync"
	"time"
)

// rateLimiter is a small per-key token bucket. It caps how many uploads a
// single client IP can start within a rolling window, so one peer can't spam
// the relay or exhaust its disk. It is deliberately simple and in-memory:
// state resets on restart, which is fine for an abuse speed-bump.
type rateLimiter struct {
	mu     sync.Mutex
	hits   map[string][]time.Time
	limit  int
	window time.Duration
	lastGC time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		hits:   make(map[string][]time.Time),
		limit:  limit,
		window: window,
	}
}

// allow records a request for key and reports whether it is within the limit.
func (rl *rateLimiter) allow(key string) bool {
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.gc(now)

	cutoff := now.Add(-rl.window)
	kept := rl.hits[key][:0]
	for _, t := range rl.hits[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= rl.limit {
		rl.hits[key] = kept
		return false
	}
	rl.hits[key] = append(kept, now)
	return true
}

// gc drops keys with no recent activity so the map can't grow unbounded. It
// runs at most once per window.
func (rl *rateLimiter) gc(now time.Time) {
	if now.Sub(rl.lastGC) < rl.window {
		return
	}
	rl.lastGC = now
	cutoff := now.Add(-rl.window)
	for key, times := range rl.hits {
		fresh := false
		for _, t := range times {
			if t.After(cutoff) {
				fresh = true
				break
			}
		}
		if !fresh {
			delete(rl.hits, key)
		}
	}
}
