package pow

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"noaddx/internal/config"
	"noaddx/internal/models"
)

// Every test drives the real issuer and validator: challenges come from GenerateChallenge,
// solutions are brute-forced with SHA-256 exactly like the browser worker does.

// newClientKey returns a fresh CSPRNG client key so per-client rate limits never collide.
func newClientKey(t testing.TB) string {
	t.Helper()
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("crypto/rand: %v", err)
	}
	return hex.EncodeToString(raw)
}

func issue(t testing.TB) *models.PoWChallenge {
	t.Helper()
	t.Setenv("POW_DIFFICULTY", "18")
	ch, err := GenerateChallenge(newClientKey(t))
	if err != nil {
		t.Fatalf("GenerateChallenge: %v", err)
	}
	return ch
}

// search returns the first nonce whose hash does (want=true) or does not (want=false)
// meet the challenge's difficulty.
func search(t testing.TB, ch *models.PoWChallenge, want bool) string {
	t.Helper()
	for nonce := 0; nonce < 1<<26; nonce++ {
		n := strconv.Itoa(nonce)
		sum := sha256.Sum256([]byte(ch.Challenge + n + ch.Salt))
		if hasNLeadingZeros(sum[:], ch.Difficulty) == want {
			return n
		}
	}
	t.Fatal("nonce search exhausted")
	return ""
}

func solutionFor(ch *models.PoWChallenge, nonce string) *models.PoWSolution {
	return &models.PoWSolution{Challenge: ch.Challenge, Salt: ch.Salt, Solution: nonce,
		Difficulty: ch.Difficulty, Timestamp: ch.Timestamp, TTL: ch.TTL}
}

func registryEntry(ch *models.PoWChallenge) (*ChallengeEntry, bool) {
	challengeMutex.RLock()
	defer challengeMutex.RUnlock()
	entry, ok := issuedChallenges[ch.Challenge+ch.Salt]
	return entry, ok
}

func TestGenerateChallenge_IssuesStoredUnusedChallenge(t *testing.T) {
	ch := issue(t)
	if !isHexOfLen(ch.Challenge, challengeBytesLen) || !isHexOfLen(ch.Salt, saltBytesLen) {
		t.Fatalf("challenge/salt not %d-byte hex: %q %q", challengeBytesLen, ch.Challenge, ch.Salt)
	}
	if ch.Difficulty != 18 || ch.TTL != int64(config.GetPoWChallengeTTL()/time.Second) {
		t.Fatalf("unexpected difficulty/ttl: %d/%d", ch.Difficulty, ch.TTL)
	}
	entry, ok := registryEntry(ch)
	if !ok || entry.Used || entry.Difficulty != ch.Difficulty || !time.Now().Before(entry.ExpiresAt) {
		t.Fatalf("registry entry wrong: %+v (present=%v)", entry, ok)
	}
}

func TestValidateSolution_AcceptsRealSolutionExactlyOnce(t *testing.T) {
	ch := issue(t)
	solution := solutionFor(ch, search(t, ch, true))
	if !ValidateSolution(solution) {
		t.Fatal("a real solution was rejected")
	}
	if ValidateSolution(solution) {
		t.Fatal("a used challenge was accepted again (replay)")
	}
}

func TestValidateSolution_RejectsNonceBelowDifficulty(t *testing.T) {
	ch := issue(t)
	if ValidateSolution(solutionFor(ch, search(t, ch, false))) {
		t.Fatal("a nonce that misses the difficulty was accepted")
	}
	// A failed attempt must not burn the challenge: the real solution still works
	if !ValidateSolution(solutionFor(ch, search(t, ch, true))) {
		t.Fatal("real solution rejected after a failed attempt")
	}
}

// Regression: difficulty must come from the server-side entry, never the client.
func TestValidateSolution_IgnoresClientDifficulty(t *testing.T) {
	ch := issue(t)
	forged := solutionFor(ch, search(t, ch, false))
	forged.Difficulty = 0
	if ValidateSolution(forged) {
		t.Fatal("client-chosen difficulty=0 was honoured")
	}
}

func TestValidateSolution_RejectsUnissuedChallenge(t *testing.T) {
	ch := issue(t)
	unissued := *ch
	unissued.Challenge = newClientKey(t) // fresh CSPRNG bytes the server never issued
	if ValidateSolution(solutionFor(&unissued, search(t, &unissued, true))) {
		t.Fatal("a solution for a challenge the server never issued was accepted")
	}
}

func TestValidateSolution_RejectsMalformedFields(t *testing.T) {
	ch := issue(t)
	nonce := search(t, ch, true)
	cases := []models.PoWSolution{
		{Challenge: ch.Challenge, Salt: ch.Salt, Solution: ""},
		{Challenge: ch.Challenge, Salt: ch.Salt, Solution: nonce + "a"},
		{Challenge: ch.Challenge, Salt: ch.Salt, Solution: "123456789012345678901"},
		{Challenge: ch.Challenge + "00", Salt: ch.Salt, Solution: nonce},
		{Challenge: ch.Challenge, Salt: "ZZ" + ch.Salt[2:], Solution: nonce},
	}
	for i := range cases {
		if ValidateSolution(&cases[i]) {
			t.Fatalf("case %d: malformed solution accepted", i)
		}
	}
	if !ValidateSolution(solutionFor(ch, nonce)) {
		t.Fatal("malformed attempts must not burn the challenge")
	}
}

func TestValidateSolution_ExpiresAfterTTL(t *testing.T) {
	t.Setenv("POW_CHALLENGE_TTL_SEC", "1")
	ch := issue(t)
	solution := solutionFor(ch, search(t, ch, true))
	time.Sleep(1100 * time.Millisecond)
	if ValidateSolution(solution) {
		t.Fatal("an expired challenge was accepted")
	}
	if _, ok := registryEntry(ch); ok {
		t.Fatal("expired challenge was not removed on validation")
	}
}

func TestValidateSolution_ConcurrentSubmissionsAcceptOnce(t *testing.T) {
	ch := issue(t)
	solution := solutionFor(ch, search(t, ch, true))
	var accepted int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := *solution
			if ValidateSolution(&s) {
				atomic.AddInt32(&accepted, 1)
			}
		}()
	}
	wg.Wait()
	if accepted != 1 {
		t.Fatalf("%d concurrent submissions accepted, want exactly 1", accepted)
	}
}

func TestGenerateChallenge_RateLimitedPerClient(t *testing.T) {
	t.Setenv("POW_DIFFICULTY", "18")
	client := newClientKey(t)
	for i := 0; i < challengesPerWindow; i++ {
		if _, err := GenerateChallenge(client); err != nil {
			t.Fatalf("request %d within the window rejected: %v", i, err)
		}
	}
	if _, err := GenerateChallenge(client); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("request beyond the window = %v, want rate limit", err)
	}
	if _, err := GenerateChallenge(newClientKey(t)); err != nil {
		t.Fatalf("another client was throttled: %v", err)
	}
}

func TestCleanup_EvictsExpiredChallengesAndIdleLimiters(t *testing.T) {
	t.Setenv("POW_CHALLENGE_TTL_SEC", "1")
	t.Setenv("POW_DIFFICULTY", "18")
	client := newClientKey(t)
	ch, err := GenerateChallenge(client)
	if err != nil {
		t.Fatalf("GenerateChallenge: %v", err)
	}
	time.Sleep(1100 * time.Millisecond)

	cleanupExpiredChallenges(time.Now())
	if _, ok := registryEntry(ch); ok {
		t.Fatal("expired challenge survived cleanup")
	}

	// Limiters are evicted only once idle for limiterIdleTimeout, measured at the given instant
	cleanupInactiveRateLimiters(time.Now())
	rateLimiterMutex.RLock()
	_, kept := challengeRateLimiters[client]
	rateLimiterMutex.RUnlock()
	if !kept {
		t.Fatal("a recently active limiter was evicted")
	}
	cleanupInactiveRateLimiters(time.Now().Add(limiterIdleTimeout + time.Minute))
	rateLimiterMutex.RLock()
	_, kept = challengeRateLimiters[client]
	rateLimiterMutex.RUnlock()
	if kept {
		t.Fatal("an idle limiter survived cleanup past the idle timeout")
	}
}

func TestDifficulty_ClampedToConfiguredRange(t *testing.T) {
	for env, want := range map[string]int{
		"18":  18,
		"21":  21,
		"1":   config.MinPoWDifficulty(),
		"100": config.MaxPoWDifficulty(),
	} {
		t.Setenv("POW_DIFFICULTY", env)
		if got := getAdaptiveDifficulty(); got != want {
			t.Errorf("POW_DIFFICULTY=%s → %d, want %d", env, got, want)
		}
	}
}

// Outstanding challenges are bounded no matter how many distinct clients ask: past the cap
// the issuer refuses (fail closed) instead of growing without limit.
func TestGenerateChallenge_OutstandingChallengesAreBounded(t *testing.T) {
	t.Setenv("POW_DIFFICULTY", "18")
	t.Cleanup(func() {
		challengeMutex.Lock()
		issuedChallenges = make(map[string]*ChallengeEntry)
		challengeMutex.Unlock()
	})

	refused := false
	for i := 0; i <= maxOutstandingChallenges; i++ {
		if _, err := GenerateChallenge(newClientKey(t)); err != nil {
			if !errors.Is(err, ErrCapacity) {
				t.Fatalf("challenge %d: %v, want ErrCapacity", i, err)
			}
			refused = true
			break
		}
	}
	challengeMutex.RLock()
	outstanding := len(issuedChallenges)
	challengeMutex.RUnlock()
	if !refused || outstanding > maxOutstandingChallenges {
		t.Fatalf("refused=%v outstanding=%d cap=%d", refused, outstanding, maxOutstandingChallenges)
	}
}
