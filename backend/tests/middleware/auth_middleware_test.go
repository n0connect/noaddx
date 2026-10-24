package middleware

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"noaddx/internal/auth"
	"noaddx/internal/middleware"
	"noaddx/tests/testutil"

	"github.com/golang-jwt/jwt/v5"
)

// serve runs the real middleware once and reports whether the protected handler ran.
func serve(t *testing.T, req *http.Request) (*httptest.ResponseRecorder, bool) {
	t.Helper()
	called := false
	rr := httptest.NewRecorder()
	middleware.JWTMiddleware(func(w http.ResponseWriter, r *http.Request) { called = true })(rr, req)
	return rr, called
}

func sessionCookie(value string) *http.Cookie {
	return &http.Cookie{Name: auth.AuthCookieName(), Value: value}
}

func signedToken(t *testing.T, secret string, expiresIn time.Duration) string {
	t.Helper()
	now := time.Now()
	claims := auth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    os.Getenv("JWT_ISSUER"),
			Audience:  jwt.ClaimStrings{os.Getenv("JWT_AUDIENCE")},
			Subject:   testutil.NewInternalID(t),
			IssuedAt:  jwt.NewNumericDate(now.Add(-time.Hour)),
			NotBefore: jwt.NewNumericDate(now.Add(-time.Hour)),
			ExpiresAt: jwt.NewNumericDate(now.Add(expiresIn)),
		},
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	return token
}

func TestJWTMiddleware_NoCookieIsUnauthorized(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	rr, called := serve(t, httptest.NewRequest("GET", "/api/v2/conversations", nil))
	if called || rr.Code != http.StatusUnauthorized {
		t.Fatalf("no cookie: called=%v status=%d", called, rr.Code)
	}
}

// Rejected tokens never reach the database, and the browser is told to drop the cookie
func TestJWTMiddleware_RejectsTokensThatDoNotVerify(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	otherSecret := testutil.NewAuthKey(t) + testutil.NewAuthKey(t)
	tokens := map[string]string{
		"garbage":             "invalid.token.here",
		"foreign secret":      signedToken(t, otherSecret, time.Hour),
		"expired":             signedToken(t, os.Getenv("JWT_SECRET"), -time.Minute),
		"truncated signature": signedToken(t, os.Getenv("JWT_SECRET"), time.Hour)[:100],
		"oversized":           strings.Repeat("A", 4096),
	}
	for name, token := range tokens {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v2/conversations", nil)
			req.AddCookie(sessionCookie(token))
			rr, called := serve(t, req)
			if called || rr.Code != http.StatusUnauthorized {
				t.Fatalf("called=%v status=%d", called, rr.Code)
			}
			cleared := false
			for _, ck := range rr.Result().Cookies() {
				cleared = cleared || (ck.Name == auth.AuthCookieName() && ck.MaxAge < 0)
			}
			if !cleared {
				t.Fatal("rejected session cookie was not cleared")
			}
		})
	}
}

// The Authorization header is not a credential channel, not even with a correctly signed token
func TestJWTMiddleware_IgnoresAuthorizationHeader(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	req := httptest.NewRequest("GET", "/api/v2/conversations", nil)
	req.Header.Set("Authorization", "Bearer "+signedToken(t, os.Getenv("JWT_SECRET"), time.Hour))
	rr, called := serve(t, req)
	if called || rr.Code != http.StatusUnauthorized {
		t.Fatalf("bearer header: called=%v status=%d", called, rr.Code)
	}
}
