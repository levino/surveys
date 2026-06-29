package main

import (
	"sync"
	"time"
)

type rateLimiter struct {
	mu       sync.Mutex
	hits     map[string][]int64
	window   int64
	maxInWin int
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{
		hits:     map[string][]int64{},
		window:   60 * 1000,
		maxInWin: 10,
	}
}

func (r *rateLimiter) allow(key string) bool {
	now := time.Now().UnixMilli()
	cutoff := now - r.window
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.hits) > 10000 {
		for k, ts := range r.hits {
			if len(ts) == 0 || ts[len(ts)-1] < cutoff {
				delete(r.hits, k)
			}
		}
	}

	kept := r.hits[key][:0]
	for _, t := range r.hits[key] {
		if t >= cutoff {
			kept = append(kept, t)
		}
	}
	if len(kept) >= r.maxInWin {
		r.hits[key] = kept
		return false
	}
	r.hits[key] = append(kept, now)
	return true
}
