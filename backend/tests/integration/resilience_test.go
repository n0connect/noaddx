package integration

import (
	"net/http"
	"testing"
	"time"

	"noaddx/internal/auth"
	"noaddx/internal/chat"
	"noaddx/internal/database"
	"noaddx/internal/models"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// breakDatabase points the backend at a closed port until the returned func (or the test's
// end) restores it: every query fails exactly as it does while PostgreSQL is down.
func breakDatabase(t *testing.T) func() {
	t.Helper()
	healthy := database.DB
	broken, err := gorm.Open(postgres.New(postgres.Config{
		DSN: "postgres://nobody:nothing@127.0.0.1:1/none?sslmode=disable&connect_timeout=1",
	}), &gorm.Config{DisableAutomaticPing: true, Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("open unreachable database: %v", err)
	}
	database.DB = broken
	restored := false
	restore := func() {
		if !restored {
			restored = true
			database.DB = healthy
		}
	}
	t.Cleanup(restore)
	return restore
}

// A database outage is not a wrong account number: telling the user "invalid credentials"
// would make them believe their only key is worthless.
func TestLogin_DatabaseOutageIsNotInvalidCredentials(t *testing.T) {
	mux := setup(t)
	alice := register(t, mux)

	restore := breakDatabase(t)
	rr := newClient(t, mux).do("POST", "/api/v2/login", models.LoginRequest{AuthKey: alice.authKey})
	expectStatus(t, rr, http.StatusServiceUnavailable, "login during an outage")

	restore()
	expectStatus(t, newClient(t, mux).do("POST", "/api/v2/login", models.LoginRequest{AuthKey: alice.authKey}),
		http.StatusOK, "login after the outage")
}

// The account number is shown in phase 1 and saved by the user before phase 2 creates the
// account. A phase 2 that fails for a passing reason (database outage, saturated Argon2id)
// must leave it redeemable, or the number the user just saved is silently worthless.
func TestRegister_PassingFailureKeepsTheAccountNumber(t *testing.T) {
	mux := setup(t)
	c := newClient(t, mux)
	rr := c.do("POST", "/api/v2/register", models.RegisterRequest{Confirm: false, PoW: c.solvePoW()})
	expectStatus(t, rr, http.StatusOK, "register phase 1")
	var phase1 models.RegisterResponse
	decode(t, rr, &phase1)
	confirm := func() *models.RegisterRequest {
		return &models.RegisterRequest{Confirm: true, PendingToken: phase1.PendingToken, PoW: c.solvePoW()}
	}

	restore := breakDatabase(t)
	if rr := c.do("POST", "/api/v2/register", confirm()); rr.Code < 500 {
		t.Fatalf("phase 2 during an outage: status %d, want 5xx", rr.Code)
	}
	restore()

	release := auth.HoldArgon2SlotsForTesting()
	rr = c.do("POST", "/api/v2/register", confirm())
	release()
	expectStatus(t, rr, http.StatusServiceUnavailable, "phase 2 while saturated")

	expectStatus(t, c.do("POST", "/api/v2/register", confirm()), http.StatusCreated, "phase 2 retried")
	expectStatus(t, newClient(t, mux).do("POST", "/api/v2/login", models.LoginRequest{AuthKey: registeredAuthKey(t, phase1.AccountNumber)}),
		http.StatusOK, "login with the saved number")

	// Created means used up: the token cannot create a second account
	expectStatus(t, c.do("POST", "/api/v2/register", confirm()), http.StatusUnauthorized, "phase 2 replayed")
}

// MAX_CONVERSATIONS_PER_USER only limits new conversations. An operator lowering it must
// not lock existing accounts out of their own conversations, nor out of burning or deleting.
func TestConversations_LoweredCapKeepsExistingAccountsWorking(t *testing.T) {
	mux := setup(t)
	alice, bob, carol, dave := register(t, mux), register(t, mux), register(t, mux), register(t, mux)
	first := pair(t, alice, bob)
	pair(t, alice, carol)

	t.Setenv("MAX_CONVERSATIONS_PER_USER", "1")
	rr := alice.do("GET", "/api/v2/conversations", nil)
	expectStatus(t, rr, http.StatusOK, "list above the lowered cap")
	var list models.ConversationsResponse
	decode(t, rr, &list)
	if len(list.Conversations) != 2 {
		t.Fatalf("listed %d conversations, want 2", len(list.Conversations))
	}

	rr = alice.createInvite()
	expectStatus(t, rr, http.StatusCreated, "invite")
	var invite models.InviteResponse
	decode(t, rr, &invite)
	expectStatus(t, dave.do("POST", "/api/v2/invites/redeem", models.RedeemInviteRequest{Token: invite.Token}),
		http.StatusTooManyRequests, "a third conversation")

	expectStatus(t, alice.do("DELETE", "/api/v2/conversations/"+first, nil), http.StatusNoContent, "burn above the cap")
	expectStatus(t, alice.do("DELETE", "/api/v2/me", models.DeleteAccountRequest{AuthKey: alice.authKey}),
		http.StatusOK, "delete above the cap")
}

// Lowering MESSAGE_TTL_DAYS also shortens what is already stored: no ciphertext outlives the
// retention the server now announces by more than that many days from now.
func TestRetention_LoweredTTLShortensStoredMessages(t *testing.T) {
	mux := setup(t)
	alice, bob := register(t, mux), register(t, mux)
	conv := pair(t, alice, bob)
	send(t, alice, bob, conv, 1)

	t.Setenv("MESSAGE_TTL_DAYS", "1")
	now := time.Now()
	if err := chat.NewService().PurgeExpired(now); err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if err := chat.NewService().PurgeExpired(now.Add(3 * 24 * time.Hour)); err != nil {
		t.Fatalf("PurgeExpired (3 days later): %v", err)
	}
	var left int64
	database.DB.Model(&models.Message{}).Count(&left)
	if left != 0 {
		t.Fatalf("%d messages outlived the lowered retention", left)
	}
}
