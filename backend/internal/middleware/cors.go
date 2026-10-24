package middleware

import (
	"net/http"
	"strings"
	"sync"

	"noaddx/internal/config"
	"noaddx/internal/utils"
)

var (
	allowedOrigins map[string]struct{}
	corsLogger     = utils.NewLogger("CORS")
	corsOnce       sync.Once
)

func loadAllowedOrigins() {
	corsOnce.Do(func() {
		allowedOrigins = make(map[string]struct{})

		raw := config.GetAllowedOrigins()
		if raw == "" {
			corsLogger.Warn("CORS: ALLOWED_ORIGINS not set; no origins will be allowed")
			return
		}
		if raw == "*" {
			corsLogger.Warn("CORS: wildcard origins are not allowed; no origins will be allowed")
			return
		}

		for _, o := range strings.Split(raw, ",") {
			o = strings.TrimSpace(o)
			if o == "" {
				continue
			}
			allowedOrigins[o] = struct{}{}
		}
		corsLogger.Info("CORS: whitelist enabled from ALLOWED_ORIGINS, count=%d", len(allowedOrigins))
	})
}

// isOriginAllowed checks if an origin is allowed, with flexible matching for localhost
func isOriginAllowed(origin string) bool {
	loadAllowedOrigins()

	// Exact match first
	if _, ok := allowedOrigins[origin]; ok {
		return true
	}

	// Flexible matching for localhost: allow any port for localhost origins
	if strings.HasPrefix(origin, "http://localhost:") || strings.HasPrefix(origin, "http://127.0.0.1:") {
		// Check if base localhost is in allowed origins
		if _, ok := allowedOrigins["http://localhost"]; ok && strings.HasPrefix(origin, "http://localhost:") {
			return true
		}
		if _, ok := allowedOrigins["http://127.0.0.1"]; ok && strings.HasPrefix(origin, "http://127.0.0.1:") {
			return true
		}
	}

	return false
}

func CORSMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		loadAllowedOrigins()
		origin := r.Header.Get("Origin")

		if origin != "" {
			if isOriginAllowed(origin) {
				// Echo origin
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")

				// Whitelist: exactly the methods and headers the API uses
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
				w.Header().Set("Access-Control-Max-Age", "3600")
			} else {
				// If Preflight then return error
				// SECURITY: Generic error message to prevent information leakage
				if r.Method == http.MethodOptions {
					corsLogger.Warn("CORS preflight from a non-whitelisted origin rejected")
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}
				// Don't send headers for any other requests.
			}
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent) // 204
			return
		}

		next(w, r)
	}
}
