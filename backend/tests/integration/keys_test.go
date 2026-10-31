package integration

import (
	"context"
	"encoding/hex"
	"net/http"
	"os"
	"strings"
	"testing"

	"noaddx/internal/chat"
	"noaddx/internal/database"
	"noaddx/internal/encryption"
	"noaddx/internal/models"
)

func newKeyHex(t *testing.T) string {
	t.Helper()
	return hex.EncodeToString(randomBytes(t, 32))
}

// setMasterKeys reconfigures the master keys as a restart with a new .env would.
func setMasterKeys(t *testing.T, activeID, active, old string) {
	t.Helper()
	t.Setenv("MASTER_KEY_ACTIVE_ID", activeID)
	t.Setenv("MASTER_KEY_ACTIVE", active)
	t.Setenv("MASTER_KEY_OLD", old)
	encryption.ResetMasterKeysForTesting()
	t.Cleanup(encryption.ResetMasterKeysForTesting)
	if err := encryption.InitMasterKeys(); err != nil {
		t.Fatalf("InitMasterKeys: %v", err)
	}
}

func countWhere(t *testing.T, model interface{}, query string, args ...interface{}) int64 {
	t.Helper()
	var n int64
	if err := database.DB.Model(model).Where(query, args...).Count(&n).Error; err != nil {
		t.Fatalf("count %T: %v", model, err)
	}
	return n
}

// A regenerated .env, or an old master key dropped while records still need it, must stop
// the server at startup: otherwise it runs and answers every account with errors.
func TestVerifyKeys_RefusesMasterKeysThatCannotOpenTheDatabase(t *testing.T) {
	mux := setup(t)
	alice, bob := register(t, mux), register(t, mux)
	pair(t, alice, bob)
	svc := chat.NewService()
	if err := svc.VerifyKeys(); err != nil {
		t.Fatalf("matching keys refused: %v", err)
	}

	writerID, writer, fresh := os.Getenv("MASTER_KEY_ACTIVE_ID"), os.Getenv("MASTER_KEY_ACTIVE"), newKeyHex(t)
	setMasterKeys(t, "k2", fresh, "")
	if err := svc.VerifyKeys(); err == nil || !strings.Contains(err.Error(), writerID) {
		t.Fatalf("missing master key %q: VerifyKeys = %v", writerID, err)
	}
	setMasterKeys(t, "k2", fresh, writerID+":"+newKeyHex(t))
	if err := svc.VerifyKeys(); err == nil {
		t.Fatal("a different key under the right id was accepted")
	}
	setMasterKeys(t, "k2", fresh, writerID+":"+writer)
	if err := svc.VerifyKeys(); err != nil {
		t.Fatalf("a correctly rotated configuration was refused: %v", err)
	}
}

// The pepper keys every lookup and pseudonym; a different one makes every account unreachable.
// The first run pins it, and every later start must present the same one.
func TestVerifyKeys_RefusesADifferentPepper(t *testing.T) {
	mux := setup(t)
	svc := chat.NewService()
	if err := svc.VerifyKeys(); err != nil {
		t.Fatalf("first run: %v", err)
	}
	register(t, mux)

	t.Setenv("ACCOUNT_LOOKUP_PEPPER", newKeyHex(t))
	if err := svc.VerifyKeys(); err == nil || !strings.Contains(err.Error(), "ACCOUNT_LOOKUP_PEPPER") {
		t.Fatalf("different pepper: VerifyKeys = %v", err)
	}
}

// A database from before the check carries no pin. The pepper is pinned only once stored
// records prove it, so a wrong pepper can never be pinned and then lock the right one out.
func TestVerifyKeys_PinsThePepperOnlyOnceRecordsProveIt(t *testing.T) {
	mux := setup(t)
	alice, bob := register(t, mux), register(t, mux)
	svc := chat.NewService()
	right := os.Getenv("ACCOUNT_LOOKUP_PEPPER")

	t.Setenv("ACCOUNT_LOOKUP_PEPPER", newKeyHex(t))
	if err := svc.VerifyKeys(); err != nil {
		t.Fatalf("accounts alone prove nothing about the pepper, yet VerifyKeys = %v", err)
	}
	if pinned := countWhere(t, &models.KeyCheck{}, "1 = 1"); pinned != 0 {
		t.Fatal("an unproven pepper was pinned")
	}

	t.Setenv("ACCOUNT_LOOKUP_PEPPER", right)
	pair(t, alice, bob)
	t.Setenv("ACCOUNT_LOOKUP_PEPPER", newKeyHex(t))
	if err := svc.VerifyKeys(); err == nil {
		t.Fatal("a pepper the stored conversations contradict was accepted")
	}
	t.Setenv("ACCOUNT_LOOKUP_PEPPER", right)
	if err := svc.VerifyKeys(); err != nil {
		t.Fatalf("right pepper: %v", err)
	}
	if pinned := countWhere(t, &models.KeyCheck{}, "1 = 1"); pinned != 1 {
		t.Fatal("a proven pepper was not pinned")
	}
}

// Rotation only retires a key once nothing is encrypted under it: after re-wrapping, the old
// key can leave MASTER_KEY_OLD and every account, conversation and invite keeps working.
func TestRewrap_RetiresTheOldMasterKey(t *testing.T) {
	mux := setup(t)
	alice, bob, carol := register(t, mux), register(t, mux), register(t, mux)
	conv := pair(t, alice, bob)
	send(t, alice, bob, conv, 1)
	rr := alice.createInvite()
	expectStatus(t, rr, http.StatusCreated, "invite")
	var invite models.InviteResponse
	decode(t, rr, &invite)
	room := createRoom(t, alice, 4, 24)
	inRoom := joinRoom(t, bob, room.code)
	room.say(t, "room before rotation", 1)

	oldID, oldKey, fresh := os.Getenv("MASTER_KEY_ACTIVE_ID"), os.Getenv("MASTER_KEY_ACTIVE"), newKeyHex(t)
	setMasterKeys(t, "k2", fresh, oldID+":"+oldKey)
	svc := chat.NewService()
	svc.RunRewrap(context.Background())

	for _, model := range []interface{}{&models.User{}, &models.ConversationMember{}, &models.Invite{}} {
		if n := countWhere(t, model, "master_key_id <> ?", "k2"); n != 0 {
			t.Fatalf("%d %T records still under the old key", n, model)
		}
	}

	setMasterKeys(t, "k2", fresh, "")
	if err := svc.VerifyKeys(); err != nil {
		t.Fatalf("old key still needed after re-wrapping: %v", err)
	}
	rr = bob.do("GET", "/api/v2/conversations/"+conv+"/messages", nil)
	expectStatus(t, rr, http.StatusOK, "read after rotation")
	var msgs models.MessagesResponse
	decode(t, rr, &msgs)
	if len(msgs.Messages) != 1 || open(t, bob, alice, conv, msgs.Messages[0]).Text != "message 1" {
		t.Fatalf("messages after rotation: %+v", msgs.Messages)
	}
	expectStatus(t, carol.do("POST", "/api/v2/invites/redeem", models.RedeemInviteRequest{Token: invite.Token}),
		http.StatusCreated, "redeem an invite made before rotation")
	if got := inRoom.read(t); len(got) != 1 || got[0].text != "room before rotation" {
		t.Fatalf("room after rotation: %+v", got)
	}
	inRoom.say(t, "room after rotation", 1)
	joinRoom(t, carol, room.code)
	expectStatus(t, newClient(t, mux).do("POST", "/api/v2/login", models.LoginRequest{AuthKey: alice.authKey}),
		http.StatusOK, "login after rotation")
}
