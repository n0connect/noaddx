package auth

import (
	"errors"
	"fmt"
	"time"

	"noaddx/internal/config"
	"noaddx/internal/utils"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("token expired")
	jwtLogger       = utils.NewLogger("JWT")
)

// maxTokenBytes bounds what the JWT parser ever sees; a genuine token is ~250 bytes
const maxTokenBytes = 1024

// pendingSubject marks pending-registration tokens; it can never be a valid user id
const pendingSubject = "pending_registration"

// Claims represents JWT claims with security best practices
// Uses RegisteredClaims.Subject for user UUID (standard "sub" claim)
// SessionEpoch must equal users.session_epoch; logout bumps it to revoke every token
type Claims struct {
	jwt.RegisteredClaims
	SessionEpoch int `json:"sep"`
}

// Session is the verified result of a session token
type Session struct {
	UserUUID     string
	SessionEpoch int
	IssuedAt     time.Time
}

// PendingRegistrationClaims represents JWT claims for pending registration
// Contains the pending ID that references server-side stored AccountNumber
type PendingRegistrationClaims struct {
	jwt.RegisteredClaims
	PendingID string `json:"pending_id"`
	IsPending bool   `json:"is_pending"`
}

// validateSecret ensures JWT secret meets security requirements
func validateSecret(secret string) error {
	if secret == "" {
		return errors.New("JWT_SECRET not configured")
	}
	minLen := config.GetJWTSecretMinLength()
	if minLen <= 0 {
		return errors.New("JWT_SECRET_MIN_LEN not configured")
	}
	if len(secret) < minLen {
		return fmt.Errorf("JWT_SECRET too short (minimum %d characters)", minLen)
	}
	return nil
}

func getJWTBaseConfig() (string, string, string, error) {
	secret := config.GetJWTSecret()
	if err := validateSecret(secret); err != nil {
		return "", "", "", err
	}
	issuer := config.GetJWTIssuer()
	if issuer == "" {
		return "", "", "", errors.New("JWT_ISSUER not configured")
	}
	audience := config.GetJWTAudience()
	if audience == "" {
		return "", "", "", errors.New("JWT_AUDIENCE not configured")
	}
	return secret, issuer, audience, nil
}

// SignToken creates a JWT token for the given user UUID and session epoch
// Security: Uses HS256, includes iss/aud/iat/exp/nbf claims; the subject must be an internal id
func SignToken(userUUID string, sessionEpoch int) (string, error) {
	if !utils.ValidateUUID(userUUID) || sessionEpoch < 0 {
		return "", ErrInvalidToken
	}

	secret, issuer, audience, err := getJWTBaseConfig()
	if err != nil {
		jwtLogger.Error("SignToken: %v", err)
		return "", err
	}

	expiration := config.GetJWTExpiration()
	if expiration <= 0 {
		jwtLogger.Error("SignToken: invalid JWT_EXPIRATION_MINUTES")
		return "", errors.New("JWT_EXPIRATION_MINUTES not configured")
	}
	now := time.Now()

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Audience:  jwt.ClaimStrings{audience},
			Subject:   userUUID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(expiration)),
			NotBefore: jwt.NewNumericDate(now),
		},
		SessionEpoch: sessionEpoch,
	}

	// Use HS256 (HMAC-SHA256) - symmetric signing
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		jwtLogger.LogError("SignToken", err)
		return "", err
	}

	return tokenString, nil
}

// SignPendingRegistrationToken creates a short-lived JWT for pending registration
// This token contains the pending ID that references server-side stored AccountNumber
// Security: Short expiration from config, contains is_pending flag
func SignPendingRegistrationToken(pendingID string) (string, error) {

	secret, issuer, audience, err := getJWTBaseConfig()
	if err != nil {
		jwtLogger.Error("SignPendingRegistrationToken: %v", err)
		return "", err
	}

	now := time.Now()
	expiration := config.GetPendingTokenTTL()
	if expiration <= 0 {
		jwtLogger.Error("SignPendingRegistrationToken: invalid PENDING_TOKEN_TTL_SEC")
		return "", errors.New("PENDING_TOKEN_TTL_SEC not configured")
	}

	claims := PendingRegistrationClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Audience:  jwt.ClaimStrings{audience},
			Subject:   pendingSubject,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(expiration)),
			NotBefore: jwt.NewNumericDate(now),
		},
		PendingID: pendingID,
		IsPending: true,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		jwtLogger.LogError("SignPendingRegistrationToken", err)
		return "", err
	}

	return tokenString, nil
}

// VerifyPendingRegistrationToken verifies a pending registration token and returns the
// identity derived in phase 1. Returns an error if the token is not a pending registration
// token or is invalid/expired.
func VerifyPendingRegistrationToken(tokenString string) (PendingIdentity, error) {
	if len(tokenString) == 0 || len(tokenString) > maxTokenBytes {
		return PendingIdentity{}, ErrInvalidToken
	}

	secret, issuer, audience, err := getJWTBaseConfig()
	if err != nil {
		jwtLogger.Error("VerifyPendingRegistrationToken: %v", err)
		return PendingIdentity{}, err
	}

	token, err := jwt.ParseWithClaims(tokenString, &PendingRegistrationClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			jwtLogger.Warn("VerifyPendingRegistrationToken: unexpected signing method: %v", token.Method.Alg())
			return nil, errors.New("unexpected signing method")
		}
		return []byte(secret), nil
	}, jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer(issuer),
		jwt.WithAudience(audience),
		jwt.WithExpirationRequired(),
	)

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			jwtLogger.Warn("VerifyPendingRegistrationToken: token expired")
			return PendingIdentity{}, ErrExpiredToken
		}
		jwtLogger.Warn("VerifyPendingRegistrationToken: invalid token")
		return PendingIdentity{}, ErrInvalidToken
	}

	claims, ok := token.Claims.(*PendingRegistrationClaims)
	if !ok || !token.Valid {
		jwtLogger.Warn("VerifyPendingRegistrationToken: invalid claims")
		return PendingIdentity{}, ErrInvalidToken
	}

	// Verify this is a pending registration token
	if !claims.IsPending || claims.Subject != pendingSubject {
		jwtLogger.Warn("VerifyPendingRegistrationToken: not a pending registration token")
		return PendingIdentity{}, ErrInvalidToken
	}

	if claims.PendingID == "" {
		jwtLogger.Warn("VerifyPendingRegistrationToken: pending ID is empty")
		return PendingIdentity{}, ErrInvalidToken
	}

	// The store entry is consumed here (one-time use)
	pending, err := GetPendingRegistration(claims.PendingID)
	if err != nil {
		jwtLogger.Warn("VerifyPendingRegistrationToken: no pending registration for this token")
		return PendingIdentity{}, err
	}
	return pending, nil
}

// VerifyToken verifies a JWT token and returns the session it carries
// Security: Validates signing method, issuer, audience, expiration and the subject's exact shape
func VerifyToken(tokenString string) (*Session, error) {
	if len(tokenString) == 0 || len(tokenString) > maxTokenBytes {
		return nil, ErrInvalidToken
	}

	secret, issuer, audience, err := getJWTBaseConfig()
	if err != nil {
		jwtLogger.Error("VerifyToken: %v", err)
		return nil, err
	}

	// Parse with explicit validation options
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// CRITICAL: Validate signing method to prevent algorithm confusion attacks
		// Only accept HMAC (HS256/HS384/HS512), reject RS256, ES256, none, etc.
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			jwtLogger.Warn("VerifyToken: unexpected signing method: %v", token.Method.Alg())
			return nil, errors.New("unexpected signing method")
		}
		return []byte(secret), nil
	}, jwt.WithValidMethods([]string{"HS256"}), // Explicitly allow only HS256
		jwt.WithIssuer(issuer),       // Validate issuer
		jwt.WithAudience(audience),   // Validate audience
		jwt.WithExpirationRequired(), // Require expiration
	)

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			jwtLogger.Warn("VerifyToken: token expired")
			return nil, ErrExpiredToken
		}
		jwtLogger.Warn("VerifyToken: invalid token")
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		jwtLogger.Warn("VerifyToken: token claims invalid or token not valid")
		return nil, ErrInvalidToken
	}

	// Whitelist: the subject is an internal user id (never a pending-registration token)
	if !utils.ValidateUUID(claims.Subject) || claims.IssuedAt == nil || claims.SessionEpoch < 0 {
		jwtLogger.Warn("VerifyToken: subject, issued-at or epoch claim invalid")
		return nil, ErrInvalidToken
	}

	return &Session{UserUUID: claims.Subject, SessionEpoch: claims.SessionEpoch, IssuedAt: claims.IssuedAt.Time}, nil
}
