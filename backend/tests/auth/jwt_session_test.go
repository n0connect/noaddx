package auth

import (
	"os"
	"testing"
	"time"

	"noaddx/internal/auth"
	"noaddx/tests/testutil"

	"github.com/golang-jwt/jwt/v5"
)

// signWithServerSecret signs claims exactly as the server would (same secret, issuer,
// audience, algorithm), so only the claim under test differs from a genuine token.
func signWithServerSecret(t *testing.T, claims auth.Claims) string {
	t.Helper()
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	return token
}

func serverClaims(subject string, epoch int) auth.Claims {
	now := time.Now()
	return auth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    os.Getenv("JWT_ISSUER"),
			Audience:  jwt.ClaimStrings{os.Getenv("JWT_AUDIENCE")},
			Subject:   subject,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
		},
		SessionEpoch: epoch,
	}
}

func TestSessionToken_RoundTrip(t *testing.T) {
	setupPendingJWTEnv(t)

	userID := testutil.NewInternalID(t)
	token, err := auth.SignToken(userID, 3)
	if err != nil {
		t.Fatalf("SignToken: %v", err)
	}
	session, err := auth.VerifyToken(token)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if session.UserUUID != userID || session.SessionEpoch != 3 {
		t.Fatalf("session = %+v, want subject %s epoch 3", session, userID)
	}
}

// The subject is looked up in the database: only the exact internal-id shape may reach it.
func TestSignToken_RejectsMalformedSubjects(t *testing.T) {
	setupPendingJWTEnv(t)

	for _, subject := range []string{"", "pending_registration", "../../../etc/passwd", "short", testutil.NewInternalID(t) + "x"} {
		if _, err := auth.SignToken(subject, 0); err == nil {
			t.Errorf("SignToken(%q) succeeded", subject)
		}
	}
	if _, err := auth.SignToken(testutil.NewInternalID(t), -1); err == nil {
		t.Error("SignToken accepted a negative session epoch")
	}
}

func TestVerifyToken_RejectsMalformedSubjectEvenWithValidSignature(t *testing.T) {
	setupPendingJWTEnv(t)

	for _, subject := range []string{"short", "' OR 1=1 --", testutil.NewInternalID(t)[:23] + "!"} {
		token := signWithServerSecret(t, serverClaims(subject, 0))
		if _, err := auth.VerifyToken(token); err == nil {
			t.Errorf("VerifyToken accepted subject %q", subject)
		}
	}
}

// A pending-registration token and a session token are never interchangeable.
func TestTokens_PendingAndSessionAreNotInterchangeable(t *testing.T) {
	setupPendingJWTEnv(t)

	pendingID, err := auth.GeneratePendingID()
	if err != nil {
		t.Fatalf("GeneratePendingID: %v", err)
	}
	if err := auth.StorePendingRegistration(pendingID, testutil.NewAccountNumber(t)); err != nil {
		t.Fatalf("StorePendingRegistration: %v", err)
	}
	pending, err := auth.SignPendingRegistrationToken(pendingID)
	if err != nil {
		t.Fatalf("SignPendingRegistrationToken: %v", err)
	}
	if _, err := auth.VerifyToken(pending); err == nil {
		t.Fatal("pending-registration token accepted as a session")
	}

	session, err := auth.SignToken(testutil.NewInternalID(t), 0)
	if err != nil {
		t.Fatalf("SignToken: %v", err)
	}
	if _, err := auth.VerifyPendingRegistrationToken(session); err == nil {
		t.Fatal("session token accepted as a pending registration")
	}
}
