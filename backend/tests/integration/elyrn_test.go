package integration

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"noaddress/internal/database"
	"noaddress/internal/models"
)

func TestRegisterAndLogin_UsesDerivedAuthKeyOnly(t *testing.T) {
	mux := setup(t)
	alice := register(t, mux)

	rr := alice.do("GET", "/api/v2/me", nil)
	expectStatus(t, rr, http.StatusOK, "me after register")
	var me models.MeResponse
	decode(t, rr, &me)
	if me.PublicKey != alice.publicKey {
		t.Fatalf("server public key %s != client derivation %s", me.PublicKey, alice.publicKey)
	}

	fresh := newClient(t, mux)
	expectStatus(t, fresh.do("POST", "/api/v2/login", models.LoginRequest{AuthKey: alice.authKey}), http.StatusOK, "login with auth key")
	expectStatus(t, fresh.do("GET", "/api/v2/me", nil), http.StatusOK, "me after login")

	// The raw AccountNumber is not a credential: it never has to leave the browser
	other := newClient(t, mux)
	expectStatus(t, other.do("POST", "/api/v2/login", models.LoginRequest{AuthKey: alice.accountNumber}), http.StatusUnauthorized, "login with raw account number")
	expectStatus(t, other.do("POST", "/api/v2/login", `{"account_number":"`+alice.accountNumber+`"}`), http.StatusBadRequest, "legacy login field")
}

func TestRegister_ProofOfWorkCannotBeBypassed(t *testing.T) {
	mux := setup(t)
	c := newClient(t, mux)

	expectStatus(t, c.do("POST", "/api/v2/register", nil), http.StatusPreconditionFailed, "empty body")
	expectStatus(t, c.do("POST", "/api/v2/register", models.RegisterRequest{}), http.StatusPreconditionFailed, "no pow")

	forged := c.solvePoW()
	forged.Solution, forged.Difficulty = "0", 0
	if rr := c.do("POST", "/api/v2/register", models.RegisterRequest{PoW: forged}); rr.Code == http.StatusOK {
		t.Fatal("forged difficulty=0 accepted")
	}

	// Parser differential: a trailing value used to skip middleware PoW validation
	body := `{"confirm":false,"pow":{"challenge":"00000000000000000000000000000000","solution":"1","salt":"00000000000000000000000000000000"}} {}`
	if rr := c.do("POST", "/api/v2/register", body); rr.Code == http.StatusOK {
		t.Fatal("trailing-data body bypassed PoW")
	}
}

func TestPairingAndMessaging(t *testing.T) {
	mux := setup(t)
	alice, bob := register(t, mux), register(t, mux)

	rr := alice.do("POST", "/api/v2/invites", nil)
	expectStatus(t, rr, http.StatusCreated, "create invite")
	var invite models.InviteResponse
	decode(t, rr, &invite)

	// A creator never matches their own invite, and the attempt must not consume it
	expectStatus(t, alice.do("POST", "/api/v2/invites/redeem", models.RedeemInviteRequest{Token: invite.Token}), http.StatusNotFound, "self redeem")
	rr = bob.do("POST", "/api/v2/invites/redeem", models.RedeemInviteRequest{Token: invite.Token})
	expectStatus(t, rr, http.StatusCreated, "bob redeems")
	var opened models.ConversationResponse
	decode(t, rr, &opened)
	convID := opened.Conversation.ID
	expectStatus(t, bob.do("POST", "/api/v2/invites/redeem", models.RedeemInviteRequest{Token: invite.Token}), http.StatusNotFound, "replayed invite")
	expectStatus(t, bob.do("POST", "/api/v2/invites/redeem", models.RedeemInviteRequest{Token: "short"}), http.StatusBadRequest, "malformed token")

	rr = alice.do("GET", "/api/v2/conversations", nil)
	expectStatus(t, rr, http.StatusOK, "alice list")
	var list models.ConversationsResponse
	decode(t, rr, &list)
	if len(list.Conversations) != 1 || list.Conversations[0].PeerPublicKey != bob.publicKey {
		t.Fatalf("alice sees %+v, want one conversation with bob's key", list.Conversations)
	}

	msgID := newMessageID()
	ct := fakeCiphertext(t, 300)
	rr = bob.do("POST", "/api/v2/conversations/"+convID+"/messages", models.SendMessageRequest{ID: msgID, Ciphertext: ct})
	expectStatus(t, rr, http.StatusCreated, "bob sends")
	var sent models.SendMessageResponse
	decode(t, rr, &sent)

	expectStatus(t, bob.do("POST", "/api/v2/conversations/"+convID+"/messages", models.SendMessageRequest{ID: msgID, Ciphertext: ct}), http.StatusConflict, "duplicate id")

	for _, view := range []struct {
		u    *user
		mine bool
	}{{alice, false}, {bob, true}} {
		rr = view.u.do("GET", "/api/v2/conversations/"+convID+"/messages", nil)
		expectStatus(t, rr, http.StatusOK, "list messages")
		var msgs models.MessagesResponse
		decode(t, rr, &msgs)
		if len(msgs.Messages) != 1 || msgs.Messages[0].Ciphertext != ct || msgs.Messages[0].Mine != view.mine || msgs.Messages[0].Seq != sent.Seq {
			t.Fatalf("unexpected messages %+v", msgs.Messages)
		}
	}

	rr = alice.do("GET", "/api/v2/conversations/"+convID+"/messages?after="+itoa(sent.Seq), nil)
	expectStatus(t, rr, http.StatusOK, "after cursor")
	var none models.MessagesResponse
	decode(t, rr, &none)
	if len(none.Messages) != 0 {
		t.Fatalf("after=last returned %d messages", len(none.Messages))
	}

	expectStatus(t, alice.do("POST", "/api/v2/conversations/"+convID+"/read", models.MarkReadRequest{Seq: sent.Seq}), http.StatusNoContent, "mark read")
	expectStatus(t, alice.do("POST", "/api/v2/conversations/"+convID+"/read", models.MarkReadRequest{Seq: sent.Seq + 1000}), http.StatusBadRequest, "read past end")
}

func TestConversation_NonMemberIsLockedOut(t *testing.T) {
	mux := setup(t)
	alice, bob, carol := register(t, mux), register(t, mux), register(t, mux)
	convID := pair(t, alice, bob)
	base := "/api/v2/conversations/" + convID

	expectStatus(t, carol.do("GET", base+"/messages", nil), http.StatusNotFound, "carol reads")
	expectStatus(t, carol.do("POST", base+"/messages", models.SendMessageRequest{ID: newMessageID(), Ciphertext: fakeCiphertext(t, 64)}), http.StatusNotFound, "carol writes")
	expectStatus(t, carol.do("POST", base+"/read", models.MarkReadRequest{Seq: 1}), http.StatusNotFound, "carol marks read")
	expectStatus(t, carol.do("DELETE", base, nil), http.StatusNotFound, "carol burns")

	anon := newClient(t, mux)
	expectStatus(t, anon.do("GET", base+"/messages", nil), http.StatusUnauthorized, "anonymous reads")
}

func TestMessages_InputWhitelist(t *testing.T) {
	mux := setup(t)
	alice, bob := register(t, mux), register(t, mux)
	base := "/api/v2/conversations/" + pair(t, alice, bob)

	bad := []models.SendMessageRequest{
		{ID: "not-a-uuid", Ciphertext: fakeCiphertext(t, 64)},
		{ID: strings.ToUpper(newMessageID()), Ciphertext: fakeCiphertext(t, 64)},
		{ID: newMessageID(), Ciphertext: ""},
		{ID: newMessageID(), Ciphertext: fakeCiphertext(t, 10)},   // shorter than nonce+tag
		{ID: newMessageID(), Ciphertext: fakeCiphertext(t, 9000)}, // above MAX_MESSAGE_BYTES
		{ID: newMessageID(), Ciphertext: fakeCiphertext(t, 64) + "="},
	}
	for i, req := range bad {
		expectStatus(t, alice.do("POST", base+"/messages", req), http.StatusBadRequest, "bad message "+itoa(int64(i)))
	}
	expectStatus(t, alice.do("GET", base+"/messages?limit=5", nil), http.StatusBadRequest, "unknown query param")
	expectStatus(t, alice.do("POST", base+"/messages", `{"id":"x","ciphertext":"y","extra":1}`), http.StatusBadRequest, "unknown field")
	expectStatus(t, alice.do("PUT", base+"/messages", models.SendMessageRequest{}), http.StatusMethodNotAllowed, "wrong method")
	expectStatus(t, alice.do("GET", "/api/v2/conversations/"+newMessageID()+"/members", nil), http.StatusNotFound, "unknown sub-route")
}

func TestBurn_RemovesConversationForBothSides(t *testing.T) {
	mux := setup(t)
	alice, bob := register(t, mux), register(t, mux)
	convID := pair(t, alice, bob)
	expectStatus(t, bob.do("POST", "/api/v2/conversations/"+convID+"/messages", models.SendMessageRequest{ID: newMessageID(), Ciphertext: fakeCiphertext(t, 64)}), http.StatusCreated, "send")

	expectStatus(t, alice.do("DELETE", "/api/v2/conversations/"+convID, nil), http.StatusNoContent, "burn")
	expectStatus(t, bob.do("GET", "/api/v2/conversations/"+convID+"/messages", nil), http.StatusNotFound, "bob after burn")

	var count int64
	database.DB.Model(&models.Message{}).Where("conversation_id = ?", convID).Count(&count)
	if count != 0 {
		t.Fatalf("%d ciphertexts survived the burn", count)
	}
}

func TestLogout_RevokesEverySession(t *testing.T) {
	mux := setup(t)
	alice := register(t, mux)
	second := newClient(t, mux)
	expectStatus(t, second.do("POST", "/api/v2/login", models.LoginRequest{AuthKey: alice.authKey}), http.StatusOK, "second login")
	stolen := *second.cookie

	expectStatus(t, alice.do("POST", "/api/v2/logout", nil), http.StatusOK, "logout")
	if alice.cookie != nil {
		t.Fatal("logout did not clear the cookie")
	}
	second.cookie = &stolen
	expectStatus(t, second.do("GET", "/api/v2/me", nil), http.StatusUnauthorized, "other device after logout")

	expectStatus(t, second.do("POST", "/api/v2/login", models.LoginRequest{AuthKey: alice.authKey}), http.StatusOK, "re-login")
	expectStatus(t, second.do("GET", "/api/v2/me", nil), http.StatusOK, "fresh session works")
}

func TestInvites_ActiveLimit(t *testing.T) {
	mux := setup(t)
	alice := register(t, mux)
	for i := 0; i < 5; i++ {
		expectStatus(t, alice.do("POST", "/api/v2/invites", nil), http.StatusCreated, "invite "+itoa(int64(i)))
	}
	expectStatus(t, alice.do("POST", "/api/v2/invites", nil), http.StatusTooManyRequests, "invite over limit")
}

func TestEvents_StreamPokesPeerOnMessage(t *testing.T) {
	mux := setup(t)
	alice, bob := register(t, mux), register(t, mux)
	convID := pair(t, alice, bob)

	srv := httptest.NewServer(mux)
	defer srv.Close()
	req, _ := http.NewRequest("GET", srv.URL+"/api/v2/events", nil)
	req.AddCookie(alice.cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("events connect: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("events status=%d type=%q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}

	lines := make(chan string, 16)
	go func() {
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
		close(lines)
	}()
	waitFor(t, lines, "retry: 3000")

	expectStatus(t, bob.do("POST", "/api/v2/conversations/"+convID+"/messages", models.SendMessageRequest{ID: newMessageID(), Ciphertext: fakeCiphertext(t, 64)}), http.StatusCreated, "bob sends")
	waitFor(t, lines, "event: msg")
	waitFor(t, lines, `data: {"c":"`+convID+`"}`)

	// Logout must close the stream server-side
	expectStatus(t, alice.do("POST", "/api/v2/logout", nil), http.StatusOK, "logout")
	deadline := time.After(3 * time.Second)
	for {
		select {
		case _, open := <-lines:
			if !open {
				return
			}
		case <-deadline:
			t.Fatal("event stream stayed open after logout")
		}
	}
}

func TestStorage_RevealsNoSocialGraph(t *testing.T) {
	mux := setup(t)
	alice, bob := register(t, mux), register(t, mux)
	pair(t, alice, bob)
	expectStatus(t, alice.do("POST", "/api/v2/invites", nil), http.StatusCreated, "pending invite")

	var users []models.User
	database.DB.Find(&users)
	var members []models.ConversationMember
	database.DB.Find(&members)
	var invites []models.Invite
	database.DB.Find(&invites)
	if len(members) != 2 || len(invites) != 1 {
		t.Fatalf("unexpected rows: members=%d invites=%d", len(members), len(invites))
	}
	for _, u := range users {
		for _, m := range members {
			if strings.Contains(m.MemberTag+m.PeerKeyEnc, u.UUID) || strings.Contains(m.PeerKeyEnc, u.PublicKey) {
				t.Fatal("conversation_members row links to a user in plaintext")
			}
		}
		for _, inv := range invites {
			if strings.Contains(inv.CreatorTag+inv.CreatorEnc+inv.Lookup, u.UUID) {
				t.Fatal("invites row links to a user in plaintext")
			}
		}
	}
}

func waitFor(t *testing.T, lines <-chan string, want string) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case line, open := <-lines:
			if !open {
				t.Fatalf("stream closed while waiting for %q", want)
			}
			if line == want {
				return
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %q", want)
		}
	}
}

func itoa(n int64) string {
	return strconv.FormatInt(n, 10)
}
