package handlers

import (
	"errors"
	"net/http"

	"noaddx/internal/auth"
	"noaddx/internal/identity"
	"noaddx/internal/middleware"
	"noaddx/internal/models"
	"noaddx/internal/realtime"
	"noaddx/internal/utils"
)

var logoutLogger = utils.NewLogger("LOGOUT")

// LogoutHandler revokes every session of the caller and clears the cookie.
// SECURITY: Bumping the session epoch invalidates all outstanding JWTs (all devices) and
// closes live event streams. Only a live session may do that: a token revoked earlier
// cannot end the sessions created after it. A failed revocation is reported, never hidden.
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	// The cookie goes in every case: absent, expired, revoked or live
	auth.ClearAuthCookie(w)

	user, _, err := middleware.Authenticate(r)
	switch {
	case errors.Is(err, middleware.ErrNoSession):
		// Nothing live to revoke: the browser is logged out once the cookie is gone
	case err != nil:
		logoutLogger.LogError("Authenticate", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	default:
		if err := userRepository.BumpSessionEpoch(user.UUID); err != nil {
			logoutLogger.LogError("BumpSessionEpoch", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if stream, err := identity.StreamTag(user.UUID); err == nil {
			realtime.Default.Kick(stream)
		}
		logoutLogger.Debug("LogoutHandler: sessions revoked")
	}

	utils.EncodeJSONResponse(w, models.LoginResponse{
		Success: true,
		Message: "Logged out successfully",
	}, http.StatusOK)
}
