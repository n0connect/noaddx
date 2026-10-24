package pow

import (
	"testing"

	"noaddress/internal/models"
)

// Regression: difficulty must come from the server-side challenge entry, never the client.
func TestValidateSolution_IgnoresClientDifficulty(t *testing.T) {
	ch, err := GenerateChallenge("203.0.113.7")
	if err != nil {
		t.Fatalf("GenerateChallenge failed: %v", err)
	}
	forged := &models.PoWSolution{Challenge: ch.Challenge, Salt: ch.Salt, Solution: "0", Difficulty: 0}
	if ValidateSolution(forged) {
		t.Fatal("solution with client-chosen difficulty=0 was accepted without work")
	}
}

// Regression: malformed fields are rejected before any registry lookup.
func TestValidateSolution_RejectsMalformedFields(t *testing.T) {
	ch, err := GenerateChallenge("203.0.113.8")
	if err != nil {
		t.Fatalf("GenerateChallenge failed: %v", err)
	}
	cases := []models.PoWSolution{
		{Challenge: ch.Challenge, Salt: ch.Salt, Solution: ""},
		{Challenge: ch.Challenge, Salt: ch.Salt, Solution: "12a"},
		{Challenge: ch.Challenge, Salt: ch.Salt, Solution: "123456789012345678901"},
		{Challenge: ch.Challenge + "00", Salt: ch.Salt, Solution: "1"},
		{Challenge: ch.Challenge, Salt: "ZZ" + ch.Salt[2:], Solution: "1"},
	}
	for i := range cases {
		if ValidateSolution(&cases[i]) {
			t.Fatalf("case %d: malformed solution accepted", i)
		}
	}
}
