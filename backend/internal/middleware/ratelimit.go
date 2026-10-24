package middleware

import (
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"

	"noaddx/internal/config"
	"noaddx/internal/utils"
)

var rateLimitLogger = utils.NewLogger("RATE_LIMIT")

// TokenBucket implements a simple token bucket rate limiter
type TokenBucket struct {
	tokens     int
	maxTokens  int
	refillRate time.Duration
	lastRefill time.Time
	lastAccess time.Time // Track last access time for cleanup
	mu         sync.Mutex
}

// NewTokenBucket creates a new token bucket
func NewTokenBucket(maxTokens int, refillRate time.Duration) *TokenBucket {
	now := time.Now()
	return &TokenBucket{
		tokens:     maxTokens,
		maxTokens:  maxTokens,
		refillRate: refillRate,
		lastRefill: now,
		lastAccess: now,
	}
}

// Allow checks if a request is allowed (consumes one token)
func (tb *TokenBucket) Allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	tb.lastAccess = now // Update last access time
	elapsed := now.Sub(tb.lastRefill)

	// Refill tokens based on elapsed time
	if elapsed > 0 {
		tokensToAdd := int(elapsed / tb.refillRate)
		if tokensToAdd > 0 {
			tb.tokens = tb.tokens + tokensToAdd
			if tb.tokens > tb.maxTokens {
				tb.tokens = tb.maxTokens
			}
			tb.lastRefill = now
		}
	}

	// Check if we have tokens available
	if tb.tokens > 0 {
		tb.tokens--
		return true
	}

	return false
}

// RateLimiter stores token buckets per client key (Lock order: rl.mu before bucket.mu)
type RateLimiter struct {
	buckets         map[string]*TokenBucket
	mu              sync.RWMutex
	cleanupInterval time.Duration
	lastCleanup     time.Time
	maxTokens       int
	refillInterval  time.Duration
	maxBuckets      int
}

var globalRateLimiter = &RateLimiter{
	buckets: make(map[string]*TokenBucket),
}

func (rl *RateLimiter) loadConfig() error {
	maxTokens := config.GetRateLimitMaxTokens()
	refillSec := config.GetRateLimitRefillIntervalSeconds()
	cleanupSec := config.GetRateLimitCleanupIntervalSeconds()
	maxBuckets := config.GetRateLimitMaxBuckets()
	if maxTokens <= 0 || refillSec <= 0 || cleanupSec <= 0 || maxBuckets <= 0 {
		return fmt.Errorf("rate limit config not set")
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.maxTokens = maxTokens
	rl.refillInterval = time.Duration(refillSec) * time.Second
	rl.cleanupInterval = time.Duration(cleanupSec) * time.Second
	rl.maxBuckets = maxBuckets
	if rl.lastCleanup.IsZero() {
		rl.lastCleanup = time.Now()
	}
	return nil
}

// inactivityThreshold drops buckets nobody has touched for an hour
const inactivityThreshold = time.Hour

// getBucket returns the bucket for key, creating it if needed. The bucket count is bounded
// at insertion: when the limiter is full, the least recently used tenth is evicted in one
// O(n log n) pass, so a flood of new keys costs amortised O(log n) and bounded memory.
func (rl *RateLimiter) getBucket(key string) *TokenBucket {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	if now.Sub(rl.lastCleanup) > rl.cleanupInterval {
		rl.evictInactiveLocked(now)
		rl.lastCleanup = now
	}
	if bucket, ok := rl.buckets[key]; ok {
		return bucket
	}
	if len(rl.buckets) >= rl.maxBuckets {
		rl.evictInactiveLocked(now)
	}
	if len(rl.buckets) >= rl.maxBuckets {
		rl.evictOldestLocked(len(rl.buckets) - rl.maxBuckets + 1 + rl.maxBuckets/10)
	}
	bucket := NewTokenBucket(rl.maxTokens, rl.refillInterval)
	rl.buckets[key] = bucket
	return bucket
}

func (rl *RateLimiter) lastAccess(bucket *TokenBucket) time.Time {
	bucket.mu.Lock()
	defer bucket.mu.Unlock()
	return bucket.lastAccess
}

// evictInactiveLocked removes buckets idle past inactivityThreshold. Caller holds rl.mu.
func (rl *RateLimiter) evictInactiveLocked(now time.Time) {
	for key, bucket := range rl.buckets {
		if now.Sub(rl.lastAccess(bucket)) > inactivityThreshold {
			delete(rl.buckets, key)
		}
	}
}

// evictOldestLocked removes the n least recently used buckets. Caller holds rl.mu.
func (rl *RateLimiter) evictOldestLocked(n int) {
	type entry struct {
		key        string
		lastAccess time.Time
	}
	entries := make([]entry, 0, len(rl.buckets))
	for key, bucket := range rl.buckets {
		entries = append(entries, entry{key: key, lastAccess: rl.lastAccess(bucket)})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].lastAccess.Before(entries[j].lastAccess) })
	for i := 0; i < n && i < len(entries); i++ {
		delete(rl.buckets, entries[i].key)
	}
	rateLimitLogger.Debug("RateLimiter: limiter full, evicted %d least recently used buckets", n)
}

// RateLimitMiddleware limits requests per IP for login and register endpoints
func RateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := globalRateLimiter.loadConfig(); err != nil {
			rateLimitLogger.LogError("RateLimitConfig", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		bucket := globalRateLimiter.getBucket("ip:" + ClientKey(r))

		if !bucket.Allow() {
			rateLimitLogger.Warn("Rate limit exceeded")
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}

		next(w, r)
	}
}
