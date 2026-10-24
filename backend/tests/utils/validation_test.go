package utils

import (
	"regexp"
	"testing"

	"noaddress/internal/utils"
	"noaddress/tests/testutil"
)

func TestGenerateAccountNumber_LengthAndCharset(t *testing.T) {
	// Test that generated account numbers are exactly 43 characters
	// and match base64url charset pattern
	pattern := regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

	for i := 0; i < 100; i++ {
		accountNumber, err := utils.GenerateAccountNumber()
		if err != nil {
			t.Fatalf("GenerateAccountNumber() failed: %v", err)
		}

		// Check length
		if len(accountNumber) != 43 {
			t.Errorf("GenerateAccountNumber() length = %d, want 43", len(accountNumber))
		}

		// Check charset
		if !pattern.MatchString(accountNumber) {
			t.Errorf("GenerateAccountNumber() = %q, does not match base64url pattern", accountNumber)
		}
	}
}

func TestValidateAccountNumber(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	// Every generated AccountNumber is valid
	for i := 0; i < 64; i++ {
		if account := testutil.NewAccountNumber(t); !utils.ValidateAccountNumber(account) {
			t.Fatalf("generated AccountNumber %q rejected", account)
		}
	}

	// Every corruption of a real one is rejected
	real := testutil.NewAccountNumber(t)
	at := len(real) / 2
	corrupted := map[string]string{
		"too short":       real[:len(real)-1],
		"too long":        real + real[:1],
		"contains '+'":    real[:at] + "+" + real[at+1:],
		"contains '/'":    real[:at] + "/" + real[at+1:],
		"contains '='":    real[:at] + "=" + real[at+1:],
		"contains space":  real[:at] + " " + real[at+1:],
		"non-ASCII rune":  real[:at] + "é" + real[at+2:],
		"empty":           "",
		"padded base64":   real + "=",
		"leading newline": "\n" + real[1:],
	}
	for name, input := range corrupted {
		if utils.ValidateAccountNumber(input) {
			t.Errorf("%s: %q accepted", name, input)
		}
	}
}
