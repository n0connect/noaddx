//go:build test
// +build test

package middleware

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"noaddx/internal/middleware"
	"noaddx/tests/testutil"
)

func TestRateLimitMiddleware_WithinLimit(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	// Reset rate limiter to ensure clean state
	middleware.ResetRateLimiterForTesting()

	req := httptest.NewRequest("POST", "/api/v2/login", nil)
	req.RemoteAddr = "127.0.0.1:12345"

	rr := httptest.NewRecorder()

	handlerCalled := false
	testHandler := middleware.RateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := http.HandlerFunc(testHandler)
	handler.ServeHTTP(rr, req)

	// Verify
	if !handlerCalled {
		t.Error("Handler should have been called")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("Status code = %d, want %d", rr.Code, http.StatusOK)
	}
}

// A burst of RATE_LIMIT_MAX_TOKENS (20) requests passes; the next one, sent before a token
// refills (one per 3 s), is refused with 429 and never reaches the handler.
func TestRateLimitMiddleware_ExceedsLimit(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)
	middleware.ResetRateLimiterForTesting()

	calls := 0
	handler := middleware.RateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	})
	serveOnce := func() int {
		req := httptest.NewRequest("POST", "/api/v2/login", nil)
		req.RemoteAddr = "127.0.0.1:54321"
		rr := httptest.NewRecorder()
		handler(rr, req)
		return rr.Code
	}

	for i := 0; i < 20; i++ {
		if code := serveOnce(); code != http.StatusOK {
			t.Fatalf("request %d of the burst: status %d, want 200", i+1, code)
		}
	}
	if code := serveOnce(); code != http.StatusTooManyRequests {
		t.Fatalf("request 21: status %d, want 429", code)
	}
	if calls != 20 {
		t.Fatalf("handler ran %d times, want 20", calls)
	}
}

func TestRateLimitMiddleware_DifferentIPs(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	// Reset rate limiter to ensure clean state
	middleware.ResetRateLimiterForTesting()

	handlerCalled1 := false
	handlerCalled2 := false

	testHandler := middleware.RateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.RemoteAddr == "127.0.0.1:11111" {
			handlerCalled1 = true
		} else if r.RemoteAddr == "127.0.0.2:22222" {
			handlerCalled2 = true
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := http.HandlerFunc(testHandler)

	// Request from IP1
	req1 := httptest.NewRequest("POST", "/api/v2/login", nil)
	req1.RemoteAddr = "127.0.0.1:11111"
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)

	// Request from IP2
	req2 := httptest.NewRequest("POST", "/api/v2/login", nil)
	req2.RemoteAddr = "127.0.0.2:22222"
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	// Verify both handlers were called (different IPs, separate buckets)
	if !handlerCalled1 {
		t.Error("Handler for IP1 should have been called")
	}
	if !handlerCalled2 {
		t.Error("Handler for IP2 should have been called")
	}
}

func TestRateLimitMiddleware_XRealIP(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	// Reset rate limiter to ensure clean state
	middleware.ResetRateLimiterForTesting()
	middleware.ResetTrustedProxiesForTesting()

	// Trust the reverse proxy IP so X-Real-IP is honored
	t.Setenv("TRUSTED_PROXIES", "127.0.0.1")

	req := httptest.NewRequest("POST", "/api/v2/login", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Real-IP", "192.168.1.100") // Trusted proxy header

	rr := httptest.NewRecorder()

	handlerCalled := false
	testHandler := middleware.RateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := http.HandlerFunc(testHandler)
	handler.ServeHTTP(rr, req)

	// Verify handler was called
	if !handlerCalled {
		t.Error("Handler should have been called")
	}

	// Note: We can't easily verify which IP was used for rate limiting
	// without exposing internal state, but the handler should work
}

func TestRateLimitMiddleware_TokenRefill(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	// Reset rate limiter to ensure clean state
	middleware.ResetRateLimiterForTesting()

	req := httptest.NewRequest("POST", "/api/v2/login", nil)
	req.RemoteAddr = "127.0.0.1:99999"

	handlerCalled := 0
	testHandler := middleware.RateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled++
		w.WriteHeader(http.StatusOK)
	})

	handler := http.HandlerFunc(testHandler)

	// Make 10 requests
	for i := 0; i < 10; i++ {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
	}

	// All should succeed (within limit of 20)
	if handlerCalled != 10 {
		t.Errorf("Handler called %d times, want 10", handlerCalled)
	}

	// Wait for token refill (3 seconds)
	time.Sleep(4 * time.Second)

	// Make another request (should succeed after refill)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if handlerCalled != 11 {
		t.Errorf("Handler called %d times after refill, want 11", handlerCalled)
	}
}

// The limiter's memory is bounded at insertion time, not only at the periodic cleanup:
// a flood of new client keys cannot grow it past RATE_LIMIT_MAX_BUCKETS.
func TestRateLimiter_BucketCountIsBoundedAtInsertion(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)
	t.Setenv("RATE_LIMIT_MAX_BUCKETS", "50")
	middleware.ResetRateLimiterForTesting()
	t.Cleanup(middleware.ResetRateLimiterForTesting)

	for i := 0; i < 1000; i++ {
		if !middleware.AllowKey("flood:" + strconv.Itoa(i)) {
			t.Fatalf("fresh key %d was refused", i)
		}
		if n := middleware.RateLimiterBucketCountForTesting(); n > 50 {
			t.Fatalf("after %d keys the limiter holds %d buckets, cap is 50", i+1, n)
		}
	}
}
