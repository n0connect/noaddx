package pow

import (
	"crypto/sha256"
	"testing"

	"noaddx/internal/models"
)

// A solution is accepted only when it was issued, unused, unexpired, and its hash meets
// the issued difficulty; nothing a client sends may panic the validator.
func FuzzValidateSolution(f *testing.F) {
	f.Setenv("POW_DIFFICULTY", "18")
	f.Setenv("POW_CHALLENGE_TTL_SEC", "300")
	ch := issue(f)
	f.Add(ch.Challenge, ch.Salt, "0")
	f.Add(ch.Challenge, ch.Salt, search(f, ch, false))
	f.Add("", "", "")
	f.Add(ch.Challenge+"00", ch.Salt, "1")

	f.Fuzz(func(t *testing.T, challenge, salt, solution string) {
		ok := ValidateSolution(&models.PoWSolution{Challenge: challenge, Salt: salt, Solution: solution})
		if !ok {
			return
		}
		if challenge != ch.Challenge || salt != ch.Salt {
			t.Fatalf("unissued challenge %q/%q accepted", challenge, salt)
		}
		sum := sha256.Sum256([]byte(challenge + solution + salt))
		if !hasNLeadingZeros(sum[:], ch.Difficulty) {
			t.Fatalf("solution %q accepted below difficulty %d", solution, ch.Difficulty)
		}
	})
}
