package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"noaddx/internal/middleware"
	"noaddx/tests/testutil"
)

func TestCORSMiddleware_AllowedOrigin(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	req := httptest.NewRequest("OPTIONS", "/api/v2/login", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "POST")

	rr := httptest.NewRecorder()

	testHandler := middleware.CORSMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := http.HandlerFunc(testHandler)
	handler.ServeHTTP(rr, req)

	// Verify CORS headers
	allowOrigin := rr.Header().Get("Access-Control-Allow-Origin")
	if allowOrigin == "" {
		t.Error("Access-Control-Allow-Origin header should be set")
	}

	allowMethods := rr.Header().Get("Access-Control-Allow-Methods")
	if allowMethods == "" {
		t.Error("Access-Control-Allow-Methods header should be set")
	}
}

func TestCORSMiddleware_PreflightRequest(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	req := httptest.NewRequest("OPTIONS", "/api/v2/login", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "Content-Type,Authorization")

	rr := httptest.NewRecorder()

	handlerCalled := false
	testHandler := middleware.CORSMiddleware(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	})

	handler := http.HandlerFunc(testHandler)
	handler.ServeHTTP(rr, req)

	// Preflight requests should not call the handler
	if handlerCalled {
		t.Error("Handler should not be called for preflight requests")
	}

	// Verify preflight response (should be 204 No Content)
	if rr.Code != http.StatusNoContent {
		t.Errorf("Status code = %d, want %d", rr.Code, http.StatusNoContent)
	}

	allowHeaders := rr.Header().Get("Access-Control-Allow-Headers")
	if allowHeaders == "" {
		t.Error("Access-Control-Allow-Headers header should be set for preflight")
	}
}

func TestCORSMiddleware_ActualRequest(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	req := httptest.NewRequest("POST", "/api/v2/login", nil)
	req.Header.Set("Origin", "http://localhost:3000")

	rr := httptest.NewRecorder()

	handlerCalled := false
	testHandler := middleware.CORSMiddleware(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := http.HandlerFunc(testHandler)
	handler.ServeHTTP(rr, req)

	// Actual requests should call the handler
	if !handlerCalled {
		t.Error("Handler should be called for actual requests")
	}

	// Verify CORS headers are set
	allowOrigin := rr.Header().Get("Access-Control-Allow-Origin")
	if allowOrigin == "" {
		t.Error("Access-Control-Allow-Origin header should be set")
	}
}

// Only exact origins match: no localhost port wildcard, no prefix tricks
func TestCORSMiddleware_ExactOriginMatchOnly(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)
	t.Setenv("ALLOWED_ORIGINS", "http://localhost,http://localhost:3000")
	middleware.ResetAllowedOriginsForTesting()
	t.Cleanup(middleware.ResetAllowedOriginsForTesting)

	for _, origin := range []string{"http://localhost:1234", "http://localhost:3000.evil.example", "http://localhost:30001", "https://localhost", "http://127.0.0.1:3000"} {
		req := httptest.NewRequest("GET", "/api/v2/me", nil)
		req.Header.Set("Origin", origin)
		rr := httptest.NewRecorder()
		middleware.CORSMiddleware(func(w http.ResponseWriter, r *http.Request) {})(rr, req)
		if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("origin %q was allowed (ACAO %q)", origin, got)
		}
	}

	req := httptest.NewRequest("OPTIONS", "/api/v2/login", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rr := httptest.NewRecorder()
	middleware.CORSMiddleware(func(w http.ResponseWriter, r *http.Request) {})(rr, req)
	if rr.Header().Get("Access-Control-Allow-Origin") != "http://localhost:3000" {
		t.Fatal("listed origin was not allowed")
	}
	if allowed := rr.Header().Get("Access-Control-Allow-Headers"); allowed != "Content-Type" {
		t.Fatalf("Access-Control-Allow-Headers = %q, want exactly Content-Type", allowed)
	}
}
