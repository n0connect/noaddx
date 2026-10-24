package middleware

import (
	"net/http"

	"noaddx/internal/utils"
)

var originLogger = utils.NewLogger("ORIGIN")

// stateChanging whitelists the methods that need same-origin proof; GET/HEAD/OPTIONS do not
// change state, and CORS (no credentials, exact origins) already keeps their bodies same-origin.
var stateChanging = map[string]struct{}{
	http.MethodPost:   {},
	http.MethodPut:    {},
	http.MethodPatch:  {},
	http.MethodDelete: {},
}

// SameOriginWritesMiddleware rejects state-changing requests a browser did not send from
// this origin. SameSite=Strict keeps the session cookie off cross-site requests, but
// "same-site" still includes other ports and sibling subdomains; this closes that gap.
//   - Sec-Fetch-Site present (every current browser): it must be exactly "same-origin".
//   - Otherwise Origin, when present, must be a whitelisted origin (ALLOWED_ORIGINS).
//   - Neither header: not a browser, so it holds no ambient browser cookies to abuse.
func SameOriginWritesMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := stateChanging[r.Method]; !ok {
			next(w, r)
			return
		}
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
			if site != "same-origin" {
				originLogger.Warn("cross-origin write rejected (fetch metadata)")
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		} else if origin := r.Header.Get("Origin"); origin != "" && !isOriginAllowed(origin) {
			originLogger.Warn("cross-origin write rejected (origin)")
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}
