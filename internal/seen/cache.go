// Package seen implements a time-bounded deduplication cache for packet nonces.
//
// Every node receiving a broadcast packet checks the nonce against this cache.
// If seen: drop silently (prevents infinite re-broadcast loops).
// If not seen: add and forward.
//
// Entries expire after TTL to bound memory usage. With DefaultTTL=8 hops and
// a broadcast rate of 10pkt/s across N peers, nonces need to survive only as
// long as a packet could reasonably be in transit (~30s is generous).
package seen

import (
	"sync"
	"time"
)

const DefaultExpiry = 60 * time.Second

// Cache is a concurrent-safe nonce deduplication store.
type Cache struct {
	mu      sync.Mutex
	entries map[[32]byte]time.Time
	expiry  time.Duration
}

// New creates a Cache with the given expiry duration.
func New(expiry time.Duration) *Cache {
	c := &Cache{
		entries: make(map[[32]byte]time.Time),
		expiry:  expiry,
	}
	go c.reap()
	return c
}

// Has returns true if nonce was previously added and has not expired.
func (c *Cache) Has(nonce [32]byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	exp, ok := c.entries[nonce]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(c.entries, nonce)
		return false
	}
	return true
}

// Add records nonce with the configured expiry time.
// Returns true if the nonce was not previously seen (i.e. this is new traffic).
func (c *Cache) Add(nonce [32]byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if exp, ok := c.entries[nonce]; ok && time.Now().Before(exp) {
		return false // already seen
	}
	c.entries[nonce] = time.Now().Add(c.expiry)
	return true
}

// Len returns the current number of cached entries.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// reap periodically removes expired entries to bound memory usage.
func (c *Cache) reap() {
	ticker := time.NewTicker(c.expiry / 2)
	for range ticker.C {
		now := time.Now()
		c.mu.Lock()
		for nonce, exp := range c.entries {
			if now.After(exp) {
				delete(c.entries, nonce)
			}
		}
		c.mu.Unlock()
	}
}
