package pow

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"noaddx/internal/config"
	"noaddx/internal/cryptoengine"
	"noaddx/internal/models"
	"noaddx/internal/utils"
)

type ChallengeEntry struct {
	Used       bool
	Difficulty int // Server-issued difficulty; the client's claimed value is never trusted
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

const (
	challengeBytesLen = 16
	saltBytesLen      = 16
	// Worker emits a decimal nonce below 10^7; 20 digits bounds any uint64.
	maxSolutionDigits = 20
	// Challenge rate limit per client: phase 1 + phase 2 of one registration plus retries
	challengesPerWindow = 5
	challengeWindow     = time.Minute
	// limiterIdleTimeout is how long a client's limiter survives without requests
	limiterIdleTimeout = time.Hour
	cleanupInterval    = time.Minute
	// maxCleanupCycles bounds the cleanup loop (RULES.md §8.1); one per minute outlives any deployment
	maxCleanupCycles = 1 << 26
	// maxOutstandingChallenges bounds issued-but-unexpired challenges (~200 bytes each);
	// maxTrackedClients bounds per-client limiters. Past either cap the issuer fails closed.
	maxOutstandingChallenges = 50000
	maxTrackedClients        = 50000
)

var (
	// ErrRateLimited: this client asked for too many challenges in the current window
	ErrRateLimited = errors.New("pow: rate limit exceeded")
	// ErrCapacity: the issuer is at its memory bound (flood in progress); retry later
	ErrCapacity = errors.New("pow: challenge capacity reached")
)

type RateLimiter struct {
	tokens         int
	maxTokens      int
	refillTime     time.Time
	refillInterval time.Duration
	lastAccess     time.Time // For cleanup tracking
	mutex          sync.Mutex
}

func NewRateLimiter(maxTokens int, refillInterval time.Duration) *RateLimiter {
	now := time.Now()
	return &RateLimiter{
		tokens:         maxTokens,
		maxTokens:      maxTokens,
		refillTime:     now.Add(refillInterval),
		refillInterval: refillInterval,
		lastAccess:     now,
	}
}

func (rl *RateLimiter) Allow() bool {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()
	rl.lastAccess = now

	// Refill tokens if necessary
	if now.After(rl.refillTime) {
		rl.tokens = rl.maxTokens
		rl.refillTime = now.Add(rl.refillInterval)
	}

	if rl.tokens <= 0 {
		return false
	}

	rl.tokens--
	return true
}

var (
	powLogger = utils.NewLogger("POW")
	// Track issued challenges with expiration
	issuedChallenges = make(map[string]*ChallengeEntry)
	challengeMutex   = sync.RWMutex{}
	// Rate limiter for challenge requests per IP
	challengeRateLimiters = make(map[string]*RateLimiter)
	rateLimiterMutex      = sync.RWMutex{}
)

// GenerateChallenge creates a new proof of work challenge
// clientKey is an opaque per-client pseudonym used only for rate limiting
func GenerateChallenge(clientKey string) (*models.PoWChallenge, error) {

	// Apply rate limiting per client network
	rateLimiterMutex.Lock()
	limiter, exists := challengeRateLimiters[clientKey]
	if !exists {
		if len(challengeRateLimiters) >= maxTrackedClients {
			rateLimiterMutex.Unlock()
			cleanupInactiveRateLimiters(time.Now())
			rateLimiterMutex.Lock()
		}
		if len(challengeRateLimiters) >= maxTrackedClients {
			rateLimiterMutex.Unlock()
			powLogger.Warn("Challenge issuer at client capacity")
			return nil, ErrCapacity
		}
		limiter = NewRateLimiter(challengesPerWindow, challengeWindow)
		challengeRateLimiters[clientKey] = limiter
	}
	rateLimiterMutex.Unlock()

	if !limiter.Allow() {
		powLogger.Warn("Challenge rate limit exceeded")
		return nil, ErrRateLimited
	}

	challengeBytes, err := cryptoengine.RandomBytes(challengeBytesLen)
	if err != nil {
		powLogger.LogError("RandomBytes", err)
		return nil, fmt.Errorf("failed to generate challenge: %w", err)
	}

	saltBytes, err := cryptoengine.RandomBytes(saltBytesLen)
	if err != nil {
		powLogger.LogError("RandomBytes", err)
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	difficulty := getAdaptiveDifficulty()
	powLogger.Debug("Generated PoW challenge with difficulty: %d", difficulty)

	challengeStr := hex.EncodeToString(challengeBytes)
	saltStr := hex.EncodeToString(saltBytes)

	now := time.Now()
	ttl := int64(config.GetPoWChallengeTTL() / time.Second)

	// Create challenge object
	challengeObj := &models.PoWChallenge{
		Challenge:  challengeStr,
		Timestamp:  now.Unix(),
		Difficulty: difficulty,
		TTL:        ttl,
		Salt:       saltStr,
	}

	// Store the challenge with proper lifecycle management
	challengeKey := challengeStr + saltStr
	challengeMutex.Lock()
	defer challengeMutex.Unlock()
	if len(issuedChallenges) >= maxOutstandingChallenges {
		removeExpiredLocked(now)
	}
	if len(issuedChallenges) >= maxOutstandingChallenges {
		powLogger.Warn("Challenge issuer at capacity")
		return nil, ErrCapacity
	}
	issuedChallenges[challengeKey] = &ChallengeEntry{
		Used:       false,
		Difficulty: difficulty,
		CreatedAt:  now,
		ExpiresAt:  now.Add(time.Duration(ttl) * time.Second),
	}

	return challengeObj, nil
}

// RunCleanup evicts expired challenges and idle per-client limiters every minute until ctx ends.
// Run it under utils.SafeGoSupervised.
func RunCleanup(ctx context.Context) {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for cycle := 0; cycle < maxCleanupCycles; cycle++ {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			cleanupExpiredChallenges(now)
			cleanupInactiveRateLimiters(now)
		}
	}
}

// cleanupExpiredChallenges removes challenges that expired before now
func cleanupExpiredChallenges(now time.Time) {
	challengeMutex.Lock()
	defer challengeMutex.Unlock()
	removeExpiredLocked(now)
}

// removeExpiredLocked deletes expired challenges. Caller holds challengeMutex.
func removeExpiredLocked(now time.Time) {
	cleaned := 0
	for key, entry := range issuedChallenges {
		if now.After(entry.ExpiresAt) {
			delete(issuedChallenges, key)
			cleaned++
		}
	}
	if cleaned > 0 {
		powLogger.Debug("Cleaned %d expired challenges, remaining: %d", cleaned, len(issuedChallenges))
	}
}

// cleanupInactiveRateLimiters removes limiters idle for longer than limiterIdleTimeout at now
func cleanupInactiveRateLimiters(now time.Time) {
	rateLimiterMutex.Lock()
	defer rateLimiterMutex.Unlock()

	cleaned := 0
	for key, limiter := range challengeRateLimiters {
		limiter.mutex.Lock()
		if now.Sub(limiter.lastAccess) > limiterIdleTimeout {
			delete(challengeRateLimiters, key)
			cleaned++
		}
		limiter.mutex.Unlock()
	}
	if cleaned > 0 {
		powLogger.Debug("Cleaned %d inactive rate limiters, remaining: %d", cleaned, len(challengeRateLimiters))
	}
}

// ValidateSolution validates a proof of work solution
func ValidateSolution(solution *models.PoWSolution) bool {
	if solution == nil {
		powLogger.Warn("Nil PoW solution provided")
		return false
	}

	powLogger.Debug("Validating PoW solution")

	// Whitelist the shape of every client-supplied field before touching shared state
	if !isHexOfLen(solution.Challenge, challengeBytesLen) || !isHexOfLen(solution.Salt, saltBytesLen) || !isDecimal(solution.Solution, maxSolutionDigits) {
		powLogger.Warn("Malformed PoW solution rejected")
		return false
	}

	// Atomic validation - lock once, check everything
	challengeKey := solution.Challenge + solution.Salt

	challengeMutex.Lock()
	defer challengeMutex.Unlock()

	// Check if challenge exists
	entry, exists := issuedChallenges[challengeKey]
	if !exists {
		powLogger.Warn("Unknown PoW challenge provided")
		return false
	}

	// Check if already used (replay attack)
	if entry.Used {
		powLogger.Warn("PoW challenge already used (replay attack)")
		return false
	}

	// Check expiration
	if time.Now().After(entry.ExpiresAt) {
		powLogger.Warn("PoW solution expired")
		delete(issuedChallenges, challengeKey) // Cleanup expired
		return false
	}

	// Verify the proof of work: SHA-256(challenge || nonce || salt) under the issued difficulty
	input := []byte(solution.Challenge + solution.Solution + solution.Salt)
	hash, err := cryptoengine.SHA256(input)
	if err != nil {
		powLogger.Error("SHA256 hash computation failed: %v", err)
		return false
	}

	result := hasNLeadingZeros(hash, entry.Difficulty)

	if result {
		// Mark as used BEFORE releasing lock
		entry.Used = true
		powLogger.Debug("Valid PoW solution accepted")
	} else {
		powLogger.Warn("PoW solution below the issued difficulty")
	}

	return result
}

func isHexOfLen(s string, byteLen int) bool {
	if len(s) != byteLen*2 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func isDecimal(s string, maxDigits int) bool {
	if len(s) == 0 || len(s) > maxDigits {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// hasNLeadingZeros checks if the hash has at least n leading zero bits
func hasNLeadingZeros(hash []byte, n int) bool {
	if n <= 0 {
		return true
	}

	zeroBits := 0

	for _, b := range hash {
		if b == 0 {
			zeroBits += 8
		} else {
			// Count leading zeros in this byte
			for bit := 7; bit >= 0; bit-- {
				if (b>>bit)&1 == 0 {
					zeroBits++
				} else {
					break
				}
			}
			break
		}

		if zeroBits >= n {
			break
		}
	}

	return zeroBits >= n
}

// getAdaptiveDifficulty returns the current difficulty based on recent activity
func getAdaptiveDifficulty() int {
	// This could be enhanced to check recent registration attempts
	// For now, return a configurable default
	difficulty := config.GetPoWDifficulty()
	if difficulty <= 0 {
		return config.DefaultPoWDifficulty()
	}

	// Clamp to min/max values
	if difficulty < config.MinPoWDifficulty() {
		difficulty = config.MinPoWDifficulty()
	}
	if difficulty > config.MaxPoWDifficulty() {
		difficulty = config.MaxPoWDifficulty()
	}

	return difficulty
}

// GetPoWDifficulty returns the current difficulty level
func GetPoWDifficulty() int {
	return getAdaptiveDifficulty()
}
