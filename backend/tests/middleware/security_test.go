package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"noaddress/internal/middleware"
	"noaddress/tests/testutil"
)

func TestSecurityHeadersMiddleware(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	req := httptest.NewRequest("GET", "/api/v2/conversations", nil)

	rr := httptest.NewRecorder()

	handlerCalled := false
	testHandler := middleware.SecurityHeadersMiddleware(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := http.HandlerFunc(testHandler)
	handler.ServeHTTP(rr, req)

	// Verify security headers
	headers := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	}

	for header, expectedValue := range headers {
		actualValue := rr.Header().Get(header)
		if actualValue != expectedValue {
			t.Errorf("Header %s = %q, want %q", header, actualValue, expectedValue)
		}
	}

	// Verify handler was called
	if !handlerCalled {
		t.Error("Handler should have been called")
	}
}

func TestSecurityHeadersMiddleware_PermissionsPolicy(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	req := httptest.NewRequest("GET", "/api/v2/conversations", nil)

	rr := httptest.NewRecorder()

	testHandler := middleware.SecurityHeadersMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := http.HandlerFunc(testHandler)
	handler.ServeHTTP(rr, req)

	// Verify Permissions-Policy header
	permissionsPolicy := rr.Header().Get("Permissions-Policy")
	if permissionsPolicy == "" {
		t.Error("Permissions-Policy header should be set")
	}

	// Whitelist: every powerful feature must be denied
	for _, feature := range []string{"camera=()", "microphone=()", "geolocation=()", "payment=()", "usb=()", "browsing-topics=()", "interest-cohort=()"} {
		if !strings.Contains(permissionsPolicy, feature) {
			t.Errorf("Permissions-Policy %q does not deny %s", permissionsPolicy, feature)
		}
	}
}
