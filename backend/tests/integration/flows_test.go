package integration

import (
	"bufio"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"noaddx/internal/auth"
	"noaddx/internal/chat"
	"noaddx/internal/database"
	"noaddx/internal/identity"
	"noaddx/internal/models"
	"noaddx/tests/testutil"
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

// Real response bodies: phase 1 shows the AccountNumber once, nothing after that ever does
func TestResponses_NeverEchoTheAccountNumber(t *testing.T) {
	mux := setup(t)
	c := newClient(t, mux)

	rr := c.do("POST", "/api/v2/register", models.RegisterRequest{Confirm: false, PoW: c.solvePoW()})
	expectStatus(t, rr, http.StatusOK, "phase 1")
	var phase1 map[string]interface{}
	decode(t, rr, &phase1)
	account, _ := phase1["account_number"].(string)
	pending, _ := phase1["pending_token"].(string)
	if len(account) != 43 || pending == "" {
		t.Fatalf("phase 1 body %v", phase1)
	}

	rr = c.do("POST", "/api/v2/register", models.RegisterRequest{Confirm: true, PendingToken: pending, PoW: c.solvePoW()})
	expectStatus(t, rr, http.StatusCreated, "phase 2")
	if strings.Contains(rr.Body.String(), account) {
		t.Fatal("phase 2 response echoes the AccountNumber")
	}

	authKey, _ := identity.DeriveAuthKey(account)
	rr = newClient(t, mux).do("POST", "/api/v2/login", models.LoginRequest{AuthKey: authKey})
	expectStatus(t, rr, http.StatusOK, "login")
	var login map[string]interface{}
	decode(t, rr, &login)
	if _, leaked := login["account_number"]; leaked || strings.Contains(rr.Body.String(), account) {
		t.Fatal("login response contains the AccountNumber")
	}
	if login["success"] != true {
		t.Fatalf("login body %v", login)
	}
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
	ct := seal(t, bob, alice, convID, msgID, "selam alice — gerçek uçtan uca", 1)
	rr = bob.do("POST", "/api/v2/conversations/"+convID+"/messages", models.SendMessageRequest{ID: msgID, Ciphertext: ct})
	expectStatus(t, rr, http.StatusCreated, "bob sends")
	var sent models.SendMessageResponse
	decode(t, rr, &sent)

	expectStatus(t, bob.do("POST", "/api/v2/conversations/"+convID+"/messages", models.SendMessageRequest{ID: msgID, Ciphertext: ct}), http.StatusConflict, "duplicate id")

	for _, view := range []struct {
		u, peer *user
		mine    bool
	}{{alice, bob, false}, {bob, alice, true}} {
		rr = view.u.do("GET", "/api/v2/conversations/"+convID+"/messages", nil)
		expectStatus(t, rr, http.StatusOK, "list messages")
		var msgs models.MessagesResponse
		decode(t, rr, &msgs)
		if len(msgs.Messages) != 1 || msgs.Messages[0].Ciphertext != ct || msgs.Messages[0].Mine != view.mine || msgs.Messages[0].Seq != sent.Seq {
			t.Fatalf("unexpected messages %+v", msgs.Messages)
		}
		if got := open(t, view.u, view.peer, convID, msgs.Messages[0]); got.Text != "selam alice — gerçek uçtan uca" || got.Counter != 1 {
			t.Fatalf("decrypted %+v", got)
		}
	}

	rr = alice.do("GET", "/api/v2/conversations/"+convID+"/messages?after="+itoa(sent.Seq), nil)
	expectStatus(t, rr, http.StatusOK, "after cursor")
	var none models.MessagesResponse
	decode(t, rr, &none)
	if len(none.Messages) != 0 {
		t.Fatalf("after=last returned %d messages", len(none.Messages))
	}

	expectStatus(t, alice.do("POST", "/api/v2/conversations/"+convID+"/read", models.MarkReadRequest(sent)), http.StatusNoContent, "mark read")
	expectStatus(t, alice.do("POST", "/api/v2/conversations/"+convID+"/read", models.MarkReadRequest{Seq: sent.Seq + 1000}), http.StatusBadRequest, "read past end")
}

func TestConversation_NonMemberIsLockedOut(t *testing.T) {
	mux := setup(t)
	alice, bob, carol := register(t, mux), register(t, mux), register(t, mux)
	convID := pair(t, alice, bob)
	base := "/api/v2/conversations/" + convID

	expectStatus(t, carol.do("GET", base+"/messages", nil), http.StatusNotFound, "carol reads")
	intruderID := newMessageID()
	intruder := seal(t, carol, alice, convID, intruderID, "let me in", 1)
	expectStatus(t, carol.do("POST", base+"/messages", models.SendMessageRequest{ID: intruderID, Ciphertext: intruder}), http.StatusNotFound, "carol writes")
	expectStatus(t, carol.do("POST", base+"/read", models.MarkReadRequest{Seq: 1}), http.StatusNotFound, "carol marks read")
	expectStatus(t, carol.do("DELETE", base, nil), http.StatusNotFound, "carol burns")

	anon := newClient(t, mux)
	expectStatus(t, anon.do("GET", base+"/messages", nil), http.StatusUnauthorized, "anonymous reads")
}

func TestMessages_InputWhitelist(t *testing.T) {
	mux := setup(t)
	alice, bob := register(t, mux), register(t, mux)
	convID := pair(t, alice, bob)
	base := "/api/v2/conversations/" + convID

	// Each rejected body is a real ciphertext, or one cut, grown or re-encoded the way an attacker would
	id := newMessageID()
	real := seal(t, alice, bob, convID, id, "a real message", 1)
	raw, _ := base64.RawURLEncoding.DecodeString(real)
	oversized := base64.RawURLEncoding.EncodeToString(append(append([]byte{}, raw...), randomBytes(t, 9000)...))
	bad := []models.SendMessageRequest{
		{ID: "not-a-uuid", Ciphertext: real},
		{ID: strings.ToUpper(id), Ciphertext: real},                          // non-canonical id
		{ID: id, Ciphertext: ""},                                             // empty
		{ID: id, Ciphertext: base64.RawURLEncoding.EncodeToString(raw[:10])}, // shorter than nonce+tag
		{ID: id, Ciphertext: oversized},                                      // above MAX_MESSAGE_BYTES
		{ID: id, Ciphertext: real + "="},                                     // padded base64
		{ID: id, Ciphertext: base64.StdEncoding.EncodeToString(raw)},         // wrong alphabet / padding
	}
	for i, req := range bad {
		expectStatus(t, alice.do("POST", base+"/messages", req), http.StatusBadRequest, "bad message "+itoa(int64(i)))
	}
	expectStatus(t, alice.do("POST", base+"/messages", models.SendMessageRequest{ID: id, Ciphertext: real}), http.StatusCreated, "the untouched real message")
	expectStatus(t, alice.do("GET", base+"/messages?limit=5", nil), http.StatusBadRequest, "unknown query param")
	expectStatus(t, alice.do("POST", base+"/messages", `{"id":"x","ciphertext":"y","extra":1}`), http.StatusBadRequest, "unknown field")
	expectStatus(t, alice.do("PUT", base+"/messages", models.SendMessageRequest{}), http.StatusMethodNotAllowed, "wrong method")
	expectStatus(t, alice.do("GET", "/api/v2/conversations/"+newMessageID()+"/members", nil), http.StatusNotFound, "unknown sub-route")
}

func TestBurn_RemovesConversationForBothSides(t *testing.T) {
	mux := setup(t)
	alice, bob := register(t, mux), register(t, mux)
	convID := pair(t, alice, bob)
	send(t, bob, alice, convID, 1)

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

	send(t, bob, alice, convID, 1)
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

// send posts one genuine E2E message from `from` to `to` and returns its sequence number.
func send(t *testing.T, from, to *user, convID string, counter int64) int64 {
	t.Helper()
	id := newMessageID()
	ct := seal(t, from, to, convID, id, "message "+itoa(counter), counter)
	rr := from.do("POST", "/api/v2/conversations/"+convID+"/messages", models.SendMessageRequest{ID: id, Ciphertext: ct})
	expectStatus(t, rr, http.StatusCreated, "send")
	var resp models.SendMessageResponse
	decode(t, rr, &resp)
	return resp.Seq
}

// A database dump must not reveal which conversations share a member, the order of
// activity across conversations, or how many conversations a user has.
func TestStorage_NoJoinableIdentifiers(t *testing.T) {
	mux := setup(t)
	alice, bob, carol := register(t, mux), register(t, mux), register(t, mux)
	conv1 := pair(t, alice, bob)
	conv2 := pair(t, alice, carol)
	expectStatus(t, alice.do("POST", "/api/v2/invites", nil), http.StatusCreated, "pending invite")

	if s := send(t, alice, bob, conv1, 1); s != 1 {
		t.Fatalf("first seq in conv1 = %d", s)
	}
	send(t, bob, alice, conv1, 1)
	send(t, alice, bob, conv1, 2)
	if s := send(t, carol, alice, conv2, 1); s != 1 {
		t.Fatalf("sequence numbers leak across conversations: first seq in conv2 = %d", s)
	}

	var users []models.User
	database.DB.Find(&users)
	var members []models.ConversationMember
	database.DB.Find(&members)
	var messages []models.Message
	database.DB.Find(&messages)
	var invites []models.Invite
	database.DB.Find(&invites)

	tagConversation := map[string]string{}
	for _, m := range members {
		if prev, seen := tagConversation[m.MemberTag]; seen {
			t.Fatalf("member tag reused across conversations %s and %s", prev, m.ConversationID)
		}
		tagConversation[m.MemberTag] = m.ConversationID.String()
	}
	if len(tagConversation) != 4 {
		t.Fatalf("expected 4 distinct per-conversation tags, got %d", len(tagConversation))
	}
	for _, msg := range messages {
		if tagConversation[msg.SenderTag] != msg.ConversationID.String() {
			t.Fatal("a sender tag is not scoped to its own conversation")
		}
	}
	for _, inv := range invites {
		if _, clash := tagConversation[inv.CreatorTag]; clash {
			t.Fatal("invite creator tag is joinable with a conversation tag")
		}
	}

	indexLen := map[int]bool{}
	for _, u := range users {
		if u.ConvIndexEnc == "" {
			t.Fatal("a paired user has no conversation index")
		}
		indexLen[len(u.ConvIndexEnc)] = true
		for _, id := range []string{conv1, conv2} {
			if strings.Contains(u.ConvIndexEnc, id) {
				t.Fatal("conversation index stores ids in plaintext")
			}
		}
		for _, m := range members {
			if strings.Contains(m.MemberTag+m.MemberRefEnc+m.PeerKeyEnc, u.UUID) || strings.Contains(m.PeerKeyEnc, u.PublicKey) {
				t.Fatal("conversation_members row links to a user in plaintext")
			}
		}
		for _, inv := range invites {
			if strings.Contains(inv.CreatorTag+inv.CreatorRefEnc+inv.Lookup, u.UUID) {
				t.Fatal("invites row links to a user in plaintext")
			}
		}
	}
	// Alice has 2 conversations, Bob and Carol 1: padding must hide the difference
	if len(indexLen) != 1 {
		t.Fatalf("conversation index size reveals the conversation count: %v", indexLen)
	}
}

func TestRetention_DayGranularExpiryAndPurge(t *testing.T) {
	mux := setup(t)
	alice, bob := register(t, mux), register(t, mux)
	conv := pair(t, alice, bob)
	send(t, alice, bob, conv, 1)
	send(t, bob, alice, conv, 1)

	rr := alice.do("GET", "/api/v2/me", nil)
	var me models.MeResponse
	decode(t, rr, &me)
	if me.MessageTTLDays != 7 {
		t.Fatalf("message_ttl_days = %d", me.MessageTTLDays)
	}

	var stored models.Message
	database.DB.Where("conversation_id = ? AND seq = 1", conv).First(&stored)
	want := time.Now().UTC().Truncate(24 * time.Hour).Add(7 * 24 * time.Hour)
	if !stored.ExpiresOn.UTC().Equal(want) {
		t.Fatalf("expires_on = %v, want day-granular %v", stored.ExpiresOn, want)
	}

	// Age the first message past its deletion day, then purge
	database.DB.Model(&models.Message{}).Where("conversation_id = ? AND seq = 1", conv).
		UpdateColumn("expires_on", time.Now().UTC().AddDate(0, 0, -1))
	if err := chat.NewService().PurgeExpired(time.Now()); err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	rr = bob.do("GET", "/api/v2/conversations/"+conv+"/messages", nil)
	var msgs models.MessagesResponse
	decode(t, rr, &msgs)
	if len(msgs.Messages) != 1 || msgs.Messages[0].Seq != 2 {
		t.Fatalf("after purge got %+v, want only seq 2", msgs.Messages)
	}
}

func TestRedeem_RollsBackWhenCreatorIsFull(t *testing.T) {
	mux := setup(t)
	alice, bob, carol := register(t, mux), register(t, mux), register(t, mux)
	pair(t, alice, bob)

	rr := alice.do("POST", "/api/v2/invites", nil)
	expectStatus(t, rr, http.StatusCreated, "invite")
	var invite models.InviteResponse
	decode(t, rr, &invite)

	t.Setenv("MAX_CONVERSATIONS_PER_USER", "1")
	expectStatus(t, carol.do("POST", "/api/v2/invites/redeem", models.RedeemInviteRequest{Token: invite.Token}), http.StatusTooManyRequests, "creator full")
	var pending int64
	database.DB.Model(&models.Invite{}).Count(&pending)
	if pending != 1 {
		t.Fatalf("failed redeem consumed the invite (pending=%d)", pending)
	}

	t.Setenv("MAX_CONVERSATIONS_PER_USER", "256")
	expectStatus(t, carol.do("POST", "/api/v2/invites/redeem", models.RedeemInviteRequest{Token: invite.Token}), http.StatusCreated, "redeem after limit raised")
}

func TestBurn_ClearsEveryMembersIndex(t *testing.T) {
	mux := setup(t)
	alice, bob := register(t, mux), register(t, mux)
	conv := pair(t, alice, bob)
	expectStatus(t, bob.do("DELETE", "/api/v2/conversations/"+conv, nil), http.StatusNoContent, "burn")

	var users []models.User
	database.DB.Find(&users)
	for _, u := range users {
		if u.ConvIndexEnc != "" {
			t.Fatal("burned conversation left an index entry behind")
		}
	}
	rr := alice.do("GET", "/api/v2/conversations", nil)
	var list models.ConversationsResponse
	decode(t, rr, &list)
	if len(list.Conversations) != 0 {
		t.Fatalf("alice still lists %d conversations", len(list.Conversations))
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

// Under a login flood the server queues Argon2id work and answers 503 when the queue is
// full, rather than allocating memory without bound; a 503 never reveals account state.
func TestLogin_ServiceUnavailableWhenArgon2IsSaturated(t *testing.T) {
	mux := setup(t)
	alice := register(t, mux)

	release := auth.HoldArgon2SlotsForTesting()
	defer release()
	for name, key := range map[string]string{"real account": alice.authKey, "unknown account": testutil.NewAuthKey(t)} {
		rr := newClient(t, mux).do("POST", "/api/v2/login", models.LoginRequest{AuthKey: key})
		expectStatus(t, rr, http.StatusServiceUnavailable, "login while saturated: "+name)
	}
}
