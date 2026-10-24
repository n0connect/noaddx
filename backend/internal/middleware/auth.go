package middleware

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"noaddress/internal/auth"
	"noaddress/internal/config"
	"noaddress/internal/store"
	"noaddress/internal/utils"
)

var (
	authMiddlewareLogger = utils.NewLogger("AUTH_MIDDLEWARE")
	userRepository       = store.NewUserRepository()
)

// sessionToken extracts the JWT: HttpOnly cookie first (browsers), Bearer header second (API clients)
func sessionToken(r *http.Request) string {
	if token := auth.GetAuthCookie(r); token != "" {
		return token
	}
	parts := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}

// JWTMiddleware verifies JWT token and adds user UUID to request context
// SECURITY: Token must carry the user's current session epoch (logout revokes every token)
// SECURITY: Sliding session: tokens past half their lifetime are re-issued as a fresh cookie
func JWTMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authMiddlewareLogger.Debug("JWTMiddleware: checking authentication for path: %s", r.URL.Path)

		tokenString := sessionToken(r)
		if tokenString == "" {
			authMiddlewareLogger.Warn("JWTMiddleware: missing authentication for path: %s", r.URL.Path)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		session, err := auth.VerifyToken(tokenString)
		if err != nil {
			if errors.Is(err, auth.ErrExpiredToken) {
				authMiddlewareLogger.Warn("JWTMiddleware: expired token for path: %s", r.URL.Path)
			} else {
				authMiddlewareLogger.Warn("JWTMiddleware: invalid token for path: %s", r.URL.Path)
			}
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Verify user exists and the session has not been revoked
		user, err := userRepository.FindByUUID(session.UserUUID)
		if err != nil {
			authMiddlewareLogger.LogError("UserRepository.FindByUUID", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if user.SessionEpoch != session.SessionEpoch {
			authMiddlewareLogger.Warn("JWTMiddleware: revoked session presented for path: %s", r.URL.Path)
			auth.ClearAuthCookie(w)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if time.Since(session.IssuedAt) > config.GetJWTExpiration()/2 {
			if fresh, err := auth.SignToken(user.UUID, user.SessionEpoch); err == nil {
				auth.SetAuthCookie(w, fresh)
			} else {
				authMiddlewareLogger.LogError("SignToken (refresh)", err)
			}
		}

		ctx := auth.WithUserUUID(r.Context(), user.UUID)
		next(w, r.WithContext(ctx))
	}
}
