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

// clientFromXFF walks X-Forwarded-For from the right. Each trusted proxy appends the peer it
// saw, so the first entry from the right that is not itself a trusted proxy is the client;
// anything further left was supplied by the client and is never believed.
func clientFromXFF(xff string) net.IP {
	if xff == "" {
		return nil
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := net.ParseIP(strings.TrimSpace(parts[i]))
		if ip == nil || isTrustedProxy(ip) {
			continue
		}
		return ip
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
		if ip := clientFromXFF(r.Header.Get("X-Forwarded-For")); ip != nil {
			return ip.String()
		}
		if ip := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); ip != nil && !isTrustedProxy(ip) {
			return ip.String()
		}
	}

	if remoteIP != nil {
		return remoteIP.String()
	}
	return ""
}

// ipv6SubscriberBits is the prefix one IPv6 subscriber controls (RFC 6177 assigns at least a /64)
const ipv6SubscriberBits = 64

// torCircuitPrefix holds the addresses tor gives onion-service clients
// (HiddenServiceExportCircuitID haproxy): one per circuit, the circuit ID in the low 32 bits.
// They reach us only through nginx's onion listener, which accepts the tor container alone.
var torCircuitPrefix = &net.IPNet{IP: net.ParseIP("fc00:dead:beef:4dad::"), Mask: net.CIDRMask(64, 128)}

// clientNetwork reduces an address to what one client controls: the IPv4 address itself,
// the IPv6 /64, or a single Tor circuit. Rate limits keyed on full IPv6 addresses are
// bypassed by rotation; grouping Tor's /64 would put every onion user in one bucket.
func clientNetwork(raw string) string {
	ip := net.ParseIP(raw)
	if ip == nil {
		return "unknown"
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	if torCircuitPrefix.Contains(ip) {
		return ip.String()
	}
	return ip.Mask(net.CIDRMask(ipv6SubscriberBits, 128)).String() + "/64"
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

// ClientKey returns an opaque, per-boot pseudonym for the client's network (IPv4 address or
// IPv6 /64). Rate limiters key on this instead of the raw IP. Panics if the CSPRNG fails
// (RULES.md §1.3).
func ClientKey(r *http.Request) string {
	clientKeyOnce.Do(func() {
		secret, err := cryptoengine.RandomBytes(32)
		if err != nil {
			panic("CSPRNG unavailable: " + err.Error())
		}
		clientKeySecret = secret
	})
	mac, err := cryptoengine.HMACSHA256(clientKeySecret, []byte(clientNetwork(ClientIP(r))))
	if err != nil {
		panic("HMAC unavailable: " + err.Error())
	}
	return hex.EncodeToString(mac[:16])
}
