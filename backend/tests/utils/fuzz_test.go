package utils

import (
	"bytes"
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"testing"

	"noaddx/internal/utils"
	"noaddx/tests/testutil"

	"github.com/google/uuid"
)

// Whitelist parsers: whatever is accepted must be canonical (re-encoding gives the input
// back), and nothing may panic.

func FuzzParseCanonicalUUIDv4(f *testing.F) {
	f.Add(uuid.New().String())
	f.Add(strings.ToUpper(uuid.New().String()))
	f.Add(uuid.Nil.String())
	f.Add("")
	f.Fuzz(func(t *testing.T, raw string) {
		id, ok := utils.ParseCanonicalUUIDv4(raw)
		if ok && (id.String() != raw || id.Version() != 4) {
			t.Fatalf("%q accepted as %s (version %d)", raw, id, id.Version())
		}
	})
}

func FuzzValidateInviteToken(f *testing.F) {
	testutil.SetupTestEnv(f)
	f.Cleanup(func() { testutil.TeardownTestEnv(f) })
	f.Add(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, 16)))
	f.Add(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, 16)))
	f.Add("")
	f.Fuzz(func(t *testing.T, token string) {
		raw, ok := utils.ValidateInviteToken(token)
		if ok && (len(raw) != utils.InviteTokenBytes || base64.RawURLEncoding.EncodeToString(raw) != token) {
			t.Fatalf("%q accepted as a non-canonical token", token)
		}
	})
}

func FuzzValidateCiphertext(f *testing.F) {
	testutil.SetupTestEnv(f)
	f.Cleanup(func() { testutil.TeardownTestEnv(f) })
	f.Add(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 29)))
	f.Add(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 8192)))
	f.Add(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 8193)))
	f.Add("")
	f.Fuzz(func(t *testing.T, encoded string) {
		if !utils.ValidateCiphertext(encoded) {
			return
		}
		raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
		if err != nil || len(raw) < 29 || len(raw) > 8192 || base64.RawURLEncoding.EncodeToString(raw) != encoded {
			t.Fatalf("%q accepted as ciphertext", encoded)
		}
	})
}

// The request decoder never panics, never accepts more than one JSON value, and never
// accepts nesting beyond MAX_JSON_DEPTH.
func FuzzDecodeJSONRequest(f *testing.F) {
	testutil.SetupTestEnv(f)
	f.Cleanup(func() { testutil.TeardownTestEnv(f) })
	f.Add(`{"auth_key":"x"}`)
	f.Add(`{"auth_key":"x"} {}`)
	f.Add(`{"a":{"b":{"c":1}}}`)
	f.Add(`[[[[]]]]`)
	f.Add(strings.Repeat("[", 100000))
	f.Add("")
	f.Fuzz(func(t *testing.T, body string) {
		var target struct {
			AuthKey string `json:"auth_key"`
		}
		req := httptest.NewRequest("POST", "/api/v2/login", strings.NewReader(body))
		err := utils.DecodeJSONRequest(req, &target)
		if err == nil && strings.Count(body, "{")+strings.Count(body, "[") > 2 {
			// more than MAX_JSON_DEPTH (2) opening brackets means nesting > 2 or a trailing value
			t.Fatalf("body %q accepted", body)
		}
	})
}
