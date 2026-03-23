package p2p

import (
	"sync"
	"time"
)

// SeenCache tracks recently seen block/TX hashes to prevent re-broadcast loops.
type SeenCache struct {
	mu      sync.Mutex
	entries map[string]int64 // hash -> unix timestamp
	maxAge  time.Duration
}

func NewSeenCache(maxAge time.Duration) *SeenCache {
	sc := &SeenCache{
		entries: make(map[string]int64),
		maxAge:  maxAge,
	}
	go sc.cleanupLoop()
	return sc
}

// Add marks a hash as seen. Returns false if already seen (duplicate).
func (sc *SeenCache) Add(hash string) bool {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if _, exists := sc.entries[hash]; exists {
		return false // already seen
	}
	sc.entries[hash] = time.Now().Unix()
	return true
}

// Has checks if a hash was seen recently.
func (sc *SeenCache) Has(hash string) bool {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	_, exists := sc.entries[hash]
	return exists
}

func (sc *SeenCache) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		sc.mu.Lock()
		cutoff := time.Now().Add(-sc.maxAge).Unix()
		for k, ts := range sc.entries {
			if ts < cutoff {
				delete(sc.entries, k)
			}
		}
		sc.mu.Unlock()
	}
}
