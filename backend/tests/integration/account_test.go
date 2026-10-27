package integration

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"testing"

	"noaddx/internal/database"
	"noaddx/internal/models"
)

// Erasing an account takes the account number again (as its derived auth key): a session left
// open, or a request riding on it, cannot do it alone. A refused attempt changes nothing.
func TestDeleteAccount_RequiresTheAccountNumber(t *testing.T) {
	mux := setup(t)
	alice, bob := register(t, mux), register(t, mux)
	// Deletion removes invites before it checks the key (lock order): a refusal must roll back
	expectStatus(t, alice.createInvite(), http.StatusCreated, "pending invite")

	expectStatus(t, alice.do("DELETE", "/api/v2/me", nil), http.StatusBadRequest, "no body")
	expectStatus(t, alice.do("DELETE", "/api/v2/me", models.DeleteAccountRequest{AuthKey: "short"}), http.StatusBadRequest, "malformed auth key")
	expectStatus(t, alice.do("DELETE", "/api/v2/me", models.DeleteAccountRequest{AuthKey: bob.authKey}), http.StatusForbidden, "another account's auth key")
	expectStatus(t, alice.do("DELETE", "/api/v2/me", `{"auth_key":"x"`), http.StatusBadRequest, "broken JSON")
	// A body must declare JSON, as on every other write, even when it holds the right key
	expectStatus(t, alice.doWithHeaders("DELETE", "/api/v2/me", `{"auth_key":"`+alice.authKey+`"}`,
		map[string]string{"Content-Type": "text/plain"}), http.StatusUnsupportedMediaType, "text/plain body")

	expectStatus(t, alice.do("GET", "/api/v2/me", nil), http.StatusOK, "alice after refused deletions")
	expectStatus(t, bob.do("GET", "/api/v2/me", nil), http.StatusOK, "bob untouched")
	var invites int64
	database.DB.Model(&models.Invite{}).Count(&invites)
	if invites != 1 {
		t.Fatalf("a refused deletion removed invites (left %d, want 1)", invites)
	}
}

// Deletion leaves nothing behind: every conversation is burned for both sides (and the peer is
// told at once), pending invites are gone, the account cannot log in, and its sessions are dead.
func TestDeleteAccount_ErasesEverything(t *testing.T) {
	mux := setup(t)
	alice, bob, carol := register(t, mux), register(t, mux), register(t, mux)
	withBob := pair(t, alice, bob)
	pair(t, carol, alice)
	send(t, alice, bob, withBob, 1)
	send(t, bob, alice, withBob, 1)
	expectStatus(t, alice.createInvite(), http.StatusCreated, "pending invite")
	bobAndCarol := pair(t, bob, carol)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close) // after streamEvents' cleanup: Close waits for open streams
	bobEvents := streamEvents(t, srv, bob.client)
	waitFor(t, bobEvents, "retry: 3000")

	expectStatus(t, alice.do("DELETE", "/api/v2/me", models.DeleteAccountRequest{AuthKey: alice.authKey}), http.StatusOK, "delete")
	waitFor(t, bobEvents, "event: conv")

	if alice.cookie != nil {
		t.Error("deletion left the session cookie in place")
	}
	expectStatus(t, alice.do("POST", "/api/v2/login", models.LoginRequest{AuthKey: alice.authKey}), http.StatusUnauthorized, "login after deletion")

	for name, peer := range map[string]*user{"bob": bob, "carol": carol} {
		rr := peer.do("GET", "/api/v2/conversations", nil)
		expectStatus(t, rr, http.StatusOK, name+" list")
		var list models.ConversationsResponse
		decode(t, rr, &list)
		for _, c := range list.Conversations {
			if c.PeerPublicKey == alice.publicKey {
				t.Errorf("%s still has a conversation with the deleted account", name)
			}
		}
	}
	rr := bob.do("GET", "/api/v2/conversations", nil)
	var list models.ConversationsResponse
	decode(t, rr, &list)
	if len(list.Conversations) != 1 || list.Conversations[0].ID != bobAndCarol {
		t.Fatalf("bob's unrelated conversation was affected: %+v", list.Conversations)
	}

	var users, invites, members, messages int64
	database.DB.Model(&models.User{}).Count(&users)
	database.DB.Model(&models.Invite{}).Count(&invites)
	database.DB.Model(&models.ConversationMember{}).Count(&members)
	database.DB.Model(&models.Message{}).Count(&messages)
	if users != 2 || invites != 0 || members != 2 || messages != 0 {
		t.Fatalf("left behind: users=%d invites=%d members=%d messages=%d (want 2/0/2/0)", users, invites, members, messages)
	}
}

// streamEvents opens u's event stream and returns its lines.
func streamEvents(t *testing.T, srv *httptest.Server, u *client) <-chan string {
	t.Helper()
	req, err := http.NewRequest("GET", srv.URL+"/api/v2/events", nil)
	if err != nil {
		t.Fatalf("events request: %v", err)
	}
	req.AddCookie(u.cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("events connect: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	expectStatus(t, &httptest.ResponseRecorder{Code: resp.StatusCode}, http.StatusOK, "events")
	lines := make(chan string, 64)
	go func() {
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
		close(lines)
	}()
	return lines
}
