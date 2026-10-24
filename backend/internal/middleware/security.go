package middleware

import (
	"net/http"
	"strconv"
	"strings"

	"noaddress/internal/config"
	"noaddress/internal/utils"
)

var securityLogger = utils.NewLogger("SECURITY_MIDDLEWARE")

// permissionsPolicy denies every powerful browser feature the app never uses
const permissionsPolicy = "accelerometer=(), autoplay=(), browsing-topics=(), camera=(), display-capture=(), geolocation=(), gyroscope=(), hid=(), interest-cohort=(), magnetometer=(), microphone=(), midi=(), payment=(), serial=(), usb=()"

// SecurityHeadersMiddleware adds security headers not including CSP
func SecurityHeadersMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", permissionsPolicy)

		if config.IsProductionMode() && IsRequestHTTPS(r) {
			maxAge := config.GetHSTSMaxAge()
			if maxAge > 0 {
				hsts := []string{"max-age=" + strconv.Itoa(maxAge)}
				if config.GetHSTSIncludeSubDomains() {
					hsts = append(hsts, "includeSubDomains")
				}
				if config.GetHSTSPreload() {
					hsts = append(hsts, "preload")
				}
				w.Header().Set("Strict-Transport-Security", strings.Join(hsts, "; "))
			}
		}

		if coop := config.GetSecurityHeaderCOOP(); coop != "" {
			w.Header().Set("Cross-Origin-Opener-Policy", coop)
		}
		if corp := config.GetSecurityHeaderCORP(); corp != "" {
			w.Header().Set("Cross-Origin-Resource-Policy", corp)
		}
		if coep := config.GetSecurityHeaderCOEP(); coep != "" {
			w.Header().Set("Cross-Origin-Embedder-Policy", coep)
		}

		next(w, r)
	}
}
