package handlers

import (
	"net/http"

	"noaddx/internal/auth"
	"noaddx/internal/identity"
	"noaddx/internal/models"
	"noaddx/internal/realtime"
	"noaddx/internal/utils"
)

var logoutLogger = utils.NewLogger("LOGOUT")

// LogoutHandler revokes every session of the caller and clears the cookie.
// SECURITY: Bumping the session epoch invalidates all outstanding JWTs (all devices),
// and live event streams are closed immediately. Invalid/absent tokens still clear the cookie.
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")

	token := auth.GetAuthCookie(r)
	if token != "" {
		if session, err := auth.VerifyToken(token); err == nil {
			if err := userRepository.BumpSessionEpoch(session.UserUUID); err != nil {
				logoutLogger.LogError("BumpSessionEpoch", err)
			}
			if stream, err := identity.StreamTag(session.UserUUID); err == nil {
				realtime.Default.Kick(stream)
			}
			logoutLogger.Debug("LogoutHandler: sessions revoked")
		}
	}

	// Clear the HttpOnly authentication cookie
	auth.ClearAuthCookie(w)

	utils.EncodeJSONResponse(w, models.LoginResponse{
		Success: true,
		Message: "Logged out successfully",
	}, http.StatusOK)

	logoutLogger.LogResponse(http.StatusOK, "Logout successful")
}
