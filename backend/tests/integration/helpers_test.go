package integration

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"noaddress/internal/auth"
	"noaddress/internal/e2e"
	"noaddress/internal/identity"
	"noaddress/internal/models"
	"noaddress/internal/server"
	"noaddress/tests/testutil"

	"github.com/google/uuid"
)

// TestMain fails fast and loudly when PostgreSQL is unreachable: these tests exercise the
// real database and must never report success without running.
func TestMain(m *testing.M) {
	testutil.SetupTestDatabaseEnv()
	addr := net.JoinHostPort(os.Getenv("DB_HOST"), os.Getenv("DB_PORT"))
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		fmt.Printf("FAIL integration: PostgreSQL not reachable at %s (%v)\n", addr, err)
		os.Exit(1)
	}
	conn.Close()
	os.Exit(m.Run())
}

var ipCounter uint32

// client is one browser: its own IP and its own session cookie.
type client struct {
	t      *testing.T
	mux    http.Handler
	ip     string
	cookie *http.Cookie
}

func setup(t *testing.T) http.Handler {
	t.Helper()
	testutil.SetupTestEnv(t)
	testutil.InitializeTestDatabase(t)
	testutil.CleanupTestData(t)
	t.Cleanup(func() {
		testutil.CleanupTestData(t)
		testutil.TeardownTestEnv(t)
	})
	return server.NewMux()
}

func newClient(t *testing.T, mux http.Handler) *client {
	n := atomic.AddUint32(&ipCounter, 1)
	return &client{t: t, mux: mux, ip: fmt.Sprintf("198.51.%d.%d:4000", n/250, n%250+1)}
}

// do sends body as JSON (string bodies are sent raw) and tracks the session cookie.
func (c *client) do(method, path string, body interface{}) *httptest.ResponseRecorder {
	c.t.Helper()
	var reader *bytes.Reader
	switch b := body.(type) {
	case nil:
		reader = bytes.NewReader(nil)
	case string:
		reader = bytes.NewReader([]byte(b))
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			c.t.Fatalf("marshal: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, reader)
	req.RemoteAddr = c.ip
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.cookie != nil {
		req.AddCookie(c.cookie)
	}
	rr := httptest.NewRecorder()
	c.mux.ServeHTTP(rr, req)
	for _, ck := range rr.Result().Cookies() {
		if ck.Name != auth.AuthCookieName() {
			continue
		}
		if ck.MaxAge < 0 || ck.Value == "" {
			c.cookie = nil
		} else {
			c.cookie = ck
		}
	}
	return rr
}

func decode(t *testing.T, rr *httptest.ResponseRecorder, v interface{}) {
	t.Helper()
	if err := json.Unmarshal(rr.Body.Bytes(), v); err != nil {
		t.Fatalf("decode %q: %v", rr.Body.String(), err)
	}
}

func expectStatus(t *testing.T, rr *httptest.ResponseRecorder, want int, what string) {
	t.Helper()
	if rr.Code != want {
		t.Fatalf("%s: status %d, want %d (body %q)", what, rr.Code, want, rr.Body.String())
	}
}

func leadingZeroBits(sum [32]byte) int {
	bits := 0
	for _, b := range sum {
		if b == 0 {
			bits += 8
			continue
		}
		for mask := byte(0x80); mask != 0 && b&mask == 0; mask >>= 1 {
			bits++
		}
		break
	}
	return bits
}

// solvePoW fetches a fresh challenge and brute-forces it (difficulty 18 in tests).
func (c *client) solvePoW() *models.PoWSolution {
	c.t.Helper()
	rr := c.do("GET", "/api/v2/pow/challenge", nil)
	expectStatus(c.t, rr, http.StatusOK, "pow challenge")
	var resp models.PoWChallengeResponse
	decode(c.t, rr, &resp)
	ch := resp.Challenge
	for nonce := 0; nonce < 1<<26; nonce++ {
		n := strconv.Itoa(nonce)
		if leadingZeroBits(sha256.Sum256([]byte(ch.Challenge+n+ch.Salt))) >= ch.Difficulty {
			return &models.PoWSolution{Challenge: ch.Challenge, Salt: ch.Salt, Solution: n, Difficulty: ch.Difficulty}
		}
	}
	c.t.Fatal("PoW not solved")
	return nil
}

// user is a registered identity plus a logged-in client. Its private key is derived from the
// real AccountNumber exactly as the browser does, so its messages are genuine E2E ciphertext.
type user struct {
	*client
	accountNumber string
	authKey       string
	publicKey     string
	privateKey    []byte
}

func register(t *testing.T, mux http.Handler) *user {
	t.Helper()
	c := newClient(t, mux)

	rr := c.do("POST", "/api/v2/register", models.RegisterRequest{Confirm: false, PoW: c.solvePoW()})
	expectStatus(t, rr, http.StatusOK, "register phase 1")
	var phase1 models.RegisterResponse
	decode(t, rr, &phase1)

	rr = c.do("POST", "/api/v2/register", models.RegisterRequest{Confirm: true, PendingToken: phase1.PendingToken, PoW: c.solvePoW()})
	expectStatus(t, rr, http.StatusCreated, "register phase 2")
	if c.cookie == nil {
		t.Fatal("register phase 2 did not set a session cookie")
	}

	authKey, err := identity.DeriveAuthKey(phase1.AccountNumber)
	if err != nil {
		t.Fatalf("DeriveAuthKey: %v", err)
	}
	publicKey, err := identity.DerivePublicKey(phase1.AccountNumber)
	if err != nil {
		t.Fatalf("DerivePublicKey: %v", err)
	}
	privateKey, err := identity.DeriveIdentityPrivateKey(phase1.AccountNumber)
	if err != nil {
		t.Fatalf("DeriveIdentityPrivateKey: %v", err)
	}
	return &user{client: c, accountNumber: phase1.AccountNumber, authKey: authKey, publicKey: publicKey, privateKey: privateKey}
}

// pair makes `a` invite and `b` redeem; returns the conversation ID.
func pair(t *testing.T, a, b *user) string {
	t.Helper()
	rr := a.do("POST", "/api/v2/invites", nil)
	expectStatus(t, rr, http.StatusCreated, "create invite")
	var invite models.InviteResponse
	decode(t, rr, &invite)

	rr = b.do("POST", "/api/v2/invites/redeem", models.RedeemInviteRequest{Token: invite.Token})
	expectStatus(t, rr, http.StatusCreated, "redeem invite")
	var conv models.ConversationResponse
	decode(t, rr, &conv)
	if conv.Conversation.PeerPublicKey != a.publicKey {
		t.Fatalf("redeemer got peer key %s, want creator key %s", conv.Conversation.PeerPublicKey, a.publicKey)
	}
	return conv.Conversation.ID
}

func newMessageID() string {
	return uuid.New().String()
}

// seal encrypts text from `from` to `to` in a conversation with the real client protocol.
func seal(t *testing.T, from, to *user, convID, messageID, text string, counter int64) string {
	t.Helper()
	conv := uuid.MustParse(convID)
	key, err := e2e.ConversationKey(from.privateKey, to.publicKey, conv)
	if err != nil {
		t.Fatalf("ConversationKey: %v", err)
	}
	ct, err := e2e.Encrypt(key, conv, uuid.MustParse(messageID), from.publicKey, text, time.Now().UnixMilli(), counter)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return ct
}

// open decrypts a message as `reader` in a conversation with `peer`.
func open(t *testing.T, reader, peer *user, convID string, m models.MessageDTO) *e2e.Message {
	t.Helper()
	conv := uuid.MustParse(convID)
	key, err := e2e.ConversationKey(reader.privateKey, peer.publicKey, conv)
	if err != nil {
		t.Fatalf("ConversationKey: %v", err)
	}
	sender := peer.publicKey
	if m.Mine {
		sender = reader.publicKey
	}
	msg, err := e2e.Decrypt(key, conv, uuid.MustParse(m.ID), sender, m.Ciphertext)
	if err != nil {
		t.Fatalf("Decrypt seq %d: %v", m.Seq, err)
	}
	return msg
}

// randomBytes returns CSPRNG output, used only to build adversarial (non-protocol) inputs.
func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("crypto/rand: %v", err)
	}
	return b
}
