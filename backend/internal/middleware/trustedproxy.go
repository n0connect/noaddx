package middleware

import (
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"sync"

	"noaddx/internal/config"
	"noaddx/internal/cryptoengine"
	"noaddx/internal/utils"
)

var (
	trustedProxyLogger = utils.NewLogger("TRUSTED_PROXY")
	trustedProxyOnce   sync.Once
	trustedProxyNets   []*net.IPNet
	trustedProxyIPs    []net.IP
)

func loadTrustedProxies() {
	trustedProxyOnce.Do(func() {
		raw := config.GetTrustedProxies()
		if raw == "" {
			trustedProxyLogger.Info("Trusted proxies: none configured")
			return
		}

		for _, entry := range strings.Split(raw, ",") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}

			if ip := net.ParseIP(entry); ip != nil {
				trustedProxyIPs = append(trustedProxyIPs, ip)
				continue
			}

			if _, cidr, err := net.ParseCIDR(entry); err == nil {
				trustedProxyNets = append(trustedProxyNets, cidr)
				continue
			}

			trustedProxyLogger.Warn("Trusted proxy entry ignored (invalid): %s", entry)
		}

		trustedProxyLogger.Info("Trusted proxies loaded: ips=%d cidrs=%d", len(trustedProxyIPs), len(trustedProxyNets))
	})
}

func isTrustedProxy(ip net.IP) bool {
	if ip == nil {
		return false
	}

	loadTrustedProxies()

	for _, trustedIP := range trustedProxyIPs {
		if trustedIP.Equal(ip) {
			return true
		}
	}
	for _, cidr := range trustedProxyNets {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func parseRemoteIP(remoteAddr string) net.IP {
	if remoteAddr == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return net.ParseIP(remoteAddr)
	}
	return net.ParseIP(host)
}

func firstValidIPFromXFF(xff string) net.IP {
	if xff == "" {
		return nil
	}
	for _, part := range strings.Split(xff, ",") {
		ip := net.ParseIP(strings.TrimSpace(part))
		if ip != nil {
			return ip
		}
	}
	return nil
}

// ClientIP returns the real client IP based on trusted proxy configuration.
// Forwarded headers are only trusted when the direct peer is a trusted proxy.
func ClientIP(r *http.Request) string {
	if r == nil {
		return ""
	}

	remoteIP := parseRemoteIP(r.RemoteAddr)
	if isTrustedProxy(remoteIP) {
		if ip := firstValidIPFromXFF(r.Header.Get("X-Forwarded-For")); ip != nil {
			return ip.String()
		}
		if ip := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); ip != nil {
			return ip.String()
		}
	}

	if remoteIP != nil {
		return remoteIP.String()
	}
	return ""
}

// IsRequestHTTPS returns true if the request is HTTPS, considering trusted proxy headers.
func IsRequestHTTPS(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	remoteIP := parseRemoteIP(r.RemoteAddr)
	if !isTrustedProxy(remoteIP) {
		return false
	}
	proto := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))
	return strings.EqualFold(proto, "https")
}

// clientKeySecret is generated per process and never persisted, so rate-limit buckets
// hold HMAC(ip) values that cannot be reversed even from a memory dump.
var (
	clientKeyOnce   sync.Once
	clientKeySecret []byte
)

// ClientKey returns an opaque, per-boot pseudonym for the client address. Rate limiters
// key on this instead of the raw IP. Panics if the CSPRNG fails (RULES.md §1.3).
func ClientKey(r *http.Request) string {
	clientKeyOnce.Do(func() {
		secret, err := cryptoengine.RandomBytes(32)
		if err != nil {
			panic("CSPRNG unavailable: " + err.Error())
		}
		clientKeySecret = secret
	})
	ip := ClientIP(r)
	if ip == "" {
		ip = "unknown"
	}
	mac, err := cryptoengine.HMACSHA256(clientKeySecret, []byte(ip))
	if err != nil {
		panic("HMAC unavailable: " + err.Error())
	}
	return hex.EncodeToString(mac[:16])
}
