package integration

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"noaddx/internal/auth"
	"noaddx/internal/models"
)

// The session token lives only in the HttpOnly cookie: no response body ever carries it,
// so script running on the page (or an XSS payload) can never read or exfiltrate it.
func TestSession_TokenNeverAppearsInResponseBodies(t *testing.T) {
	mux := setup(t)
	c := newClient(t, mux)

	rr := c.do("POST", "/api/v2/register", models.RegisterRequest{Confirm: false, PoW: c.solvePoW()})
	expectStatus(t, rr, http.StatusOK, "phase 1")
	var phase1 models.RegisterResponse
	decode(t, rr, &phase1)

	rr = c.do("POST", "/api/v2/register", models.RegisterRequest{Confirm: true, PendingToken: phase1.PendingToken, PoW: c.solvePoW()})
	expectStatus(t, rr, http.StatusCreated, "phase 2")
	assertNoTokenField(t, rr, "register phase 2")
	if c.cookie == nil || !c.cookie.HttpOnly || c.cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie must be HttpOnly + SameSite=Strict, got %+v", c.cookie)
	}

	authKey := registeredAuthKey(t, phase1.AccountNumber)
	login := newClient(t, mux)
	rr = login.do("POST", "/api/v2/login", models.LoginRequest{AuthKey: authKey})
	expectStatus(t, rr, http.StatusOK, "login")
	assertNoTokenField(t, rr, "login")
	if login.cookie == nil || !login.cookie.HttpOnly {
		t.Fatal("login did not set an HttpOnly session cookie")
	}
}

// One authentication channel: a valid JWT presented as a Bearer header is not a session.
func TestSession_BearerHeaderIsNotACredential(t *testing.T) {
	mux := setup(t)
	alice := register(t, mux)

	req := httptest.NewRequest("GET", "/api/v2/me", nil)
	req.RemoteAddr = alice.ip
	req.Header.Set("Authorization", "Bearer "+alice.cookie.Value)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	expectStatus(t, rr, http.StatusUnauthorized, "valid JWT as bearer header")
}

// A token revoked by an earlier logout must not be able to revoke the sessions created after it.
func TestLogout_RevokedTokenCannotEndNewerSessions(t *testing.T) {
	mux := setup(t)
	alice := register(t, mux)
	stale := *alice.cookie

	expectStatus(t, alice.do("POST", "/api/v2/logout", nil), http.StatusOK, "first logout")

	fresh := newClient(t, mux)
	expectStatus(t, fresh.do("POST", "/api/v2/login", models.LoginRequest{AuthKey: alice.authKey}), http.StatusOK, "login after logout")

	attacker := newClient(t, mux)
	attacker.cookie = &stale
	expectStatus(t, attacker.do("POST", "/api/v2/logout", nil), http.StatusOK, "logout with a revoked token")
	if attacker.cookie != nil {
		t.Fatal("logout with a revoked token did not clear that cookie")
	}
	expectStatus(t, fresh.do("GET", "/api/v2/me", nil), http.StatusOK, "newer session after a stale logout")
}

// State-changing requests a browser marks as cross-site or same-site (another port, another
// subdomain) are refused even though SameSite=Strict would carry the cookie for same-site ones.
func TestCSRF_CrossOriginWritesAreRejected(t *testing.T) {
	mux := setup(t)
	alice := register(t, mux)

	rejected := []map[string]string{
		{"Sec-Fetch-Site": "cross-site"},
		{"Sec-Fetch-Site": "same-site"},
		{"Sec-Fetch-Site": "none"},
		{"Origin": "http://evil.example"},
		{"Origin": "http://localhost:3000.evil.example"},
		{"Origin": "null"},
	}
	// The body is otherwise acceptable, so only the origin check can refuse it; the refused
	// requests never reach the handler, so the same proof of work is still unspent below
	paid := models.CreateInviteRequest{PoW: alice.freshPoW()}
	for _, headers := range rejected {
		rr := alice.doWithHeaders("POST", "/api/v2/invites", paid, headers)
		expectStatus(t, rr, http.StatusForbidden, "cross-origin write "+headerString(headers))
	}
	expectStatus(t, alice.doWithHeaders("DELETE", "/api/v2/conversations/3b241101-e2bb-4255-8caf-4136c566a962", nil,
		map[string]string{"Sec-Fetch-Site": "cross-site"}), http.StatusForbidden, "cross-site delete")

	// What a real same-origin browser request and a non-browser client look like
	expectStatus(t, alice.doWithHeaders("POST", "/api/v2/invites", paid,
		map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "http://localhost:3000"}), http.StatusCreated, "same-origin write")
	expectStatus(t, alice.createInvite(), http.StatusCreated, "client without browser metadata")
	// Reads are not state-changing: CORS (no credentials) already keeps their bodies same-origin
	expectStatus(t, alice.doWithHeaders("GET", "/api/v2/me", nil,
		map[string]string{"Sec-Fetch-Site": "cross-site"}), http.StatusOK, "cross-site read")
}

func assertNoTokenField(t *testing.T, rr *httptest.ResponseRecorder, what string) {
	t.Helper()
	var body map[string]interface{}
	decode(t, rr, &body)
	if _, present := body["token"]; present {
		t.Fatalf("%s: response body carries the session token", what)
	}
	for _, ck := range rr.Result().Cookies() {
		if ck.Name == auth.AuthCookieName() && ck.Value != "" && containsString(rr.Body.String(), ck.Value) {
			t.Fatalf("%s: response body contains the session cookie value", what)
		}
	}
}
