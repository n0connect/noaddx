package middleware

import (
	"net/http"
	"strings"

	"noaddx/internal/utils"
)

var contentTypeLogger = utils.NewLogger("CONTENT_TYPE")

// emptyBodyAllowed whitelists POST endpoints that may be called without any body.
// Every other POST/PUT must declare application/json; unknown paths never reach here (mux 404s them).
var emptyBodyAllowed = map[string]struct{}{
	"/api/v2/register": {}, // Phase 1 preview (still rejected later without PoW)
	"/api/v2/logout":   {},
}

// ContentTypeMiddleware validates Content-Type header for body-carrying methods.
func ContentTypeMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodPut:
			if _, ok := emptyBodyAllowed[r.URL.Path]; ok && r.ContentLength == 0 {
				next(w, r)
				return
			}
		case http.MethodDelete:
			// Usually bodiless; one that carries data (or an unknown length) meets the same rule
			if r.ContentLength == 0 {
				next(w, r)
				return
			}
		default:
			next(w, r)
			return
		}

		// Whitelist: Only allow "application/json" (parameters such as charset are ignored)
		baseContentType := strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])
		if !strings.EqualFold(baseContentType, "application/json") {
			contentTypeLogger.Warn("ContentTypeMiddleware: unsupported content-type rejected")
			http.Error(w, "Unsupported Media Type", http.StatusUnsupportedMediaType)
			return
		}

		next(w, r)
	}
}
