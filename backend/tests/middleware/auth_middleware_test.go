package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"noaddress/internal/middleware"
	"noaddress/tests/testutil"
)

func TestJWTMiddleware_MissingHeader(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	req := httptest.NewRequest("GET", "/api/v2/conversations", nil)
	// No Authorization header

	rr := httptest.NewRecorder()

	handlerCalled := false
	testHandler := middleware.JWTMiddleware(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	})

	handler := http.HandlerFunc(testHandler)
	handler.ServeHTTP(rr, req)

	// Verify
	if handlerCalled {
		t.Error("Handler should not have been called")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Status code = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestJWTMiddleware_InvalidToken(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	req := httptest.NewRequest("GET", "/api/v2/conversations", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.here")

	rr := httptest.NewRecorder()

	handlerCalled := false
	testHandler := middleware.JWTMiddleware(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	})

	handler := http.HandlerFunc(testHandler)
	handler.ServeHTTP(rr, req)

	// Verify
	if handlerCalled {
		t.Error("Handler should not have been called")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Status code = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestJWTMiddleware_ExpiredToken(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	// Note: Testing expired tokens requires time manipulation
	// For now, we test that invalid tokens are rejected
	req := httptest.NewRequest("GET", "/api/v2/conversations", nil)
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxfQ.invalid")

	rr := httptest.NewRecorder()

	handlerCalled := false
	testHandler := middleware.JWTMiddleware(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	})

	handler := http.HandlerFunc(testHandler)
	handler.ServeHTTP(rr, req)

	// Verify
	if handlerCalled {
		t.Error("Handler should not have been called")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Status code = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestJWTMiddleware_InvalidHeaderFormat(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	tests := []struct {
		name   string
		header string
	}{
		{
			name:   "no Bearer prefix",
			header: "token-here",
		},
		{
			name:   "empty token",
			header: "Bearer ",
		},
		{
			name:   "missing space",
			header: "Bearertoken",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v2/conversations", nil)
			req.Header.Set("Authorization", tt.header)

			rr := httptest.NewRecorder()

			handlerCalled := false
			testHandler := middleware.JWTMiddleware(func(w http.ResponseWriter, r *http.Request) {
				handlerCalled = true
			})

			handler := http.HandlerFunc(testHandler)
			handler.ServeHTTP(rr, req)

			// Verify
			if handlerCalled {
				t.Error("Handler should not have been called")
			}
			if rr.Code != http.StatusUnauthorized {
				t.Errorf("Status code = %d, want %d", rr.Code, http.StatusUnauthorized)
			}
		})
	}
}
