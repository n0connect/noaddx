package middleware

import (
	"net/http/httptest"
	"testing"

	"noaddx/internal/middleware"
	"noaddx/tests/testutil"
)

func TestClientIP_UntrustedProxy_IgnoresForwardedHeaders(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	middleware.ResetTrustedProxiesForTesting()

	req := httptest.NewRequest("GET", "/api/v2/conversations", nil)
	req.RemoteAddr = "203.0.113.10:12345"
	req.Header.Set("X-Forwarded-For", "198.51.100.20")
	req.Header.Set("X-Real-IP", "198.51.100.30")

	ip := middleware.ClientIP(req)
	if ip != "203.0.113.10" {
		t.Errorf("ClientIP() = %q, want %q", ip, "203.0.113.10")
	}
}

func TestClientIP_TrustedProxy_UsesForwardedHeaders(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	t.Setenv("TRUSTED_PROXIES", "203.0.113.0/24")
	middleware.ResetTrustedProxiesForTesting()

	req := httptest.NewRequest("GET", "/api/v2/conversations", nil)
	req.RemoteAddr = "203.0.113.10:12345"
	req.Header.Set("X-Forwarded-For", "198.51.100.20, 203.0.113.10")

	ip := middleware.ClientIP(req)
	if ip != "198.51.100.20" {
		t.Errorf("ClientIP() = %q, want %q", ip, "198.51.100.20")
	}
}

// X-Forwarded-For is read from the right: each trusted proxy appends the address it saw,
// so the first untrusted hop from the right is the only entry the chain vouches for.
// Everything left of it is whatever the client chose to send.
func TestClientIP_TrustedProxy_TakesRightmostUntrustedHop(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)
	t.Setenv("TRUSTED_PROXIES", "203.0.113.0/24")
	middleware.ResetTrustedProxiesForTesting()
	t.Cleanup(middleware.ResetTrustedProxiesForTesting)

	cases := map[string]string{
		"1.2.3.4, 198.51.100.20":                    "198.51.100.20", // spoofed entry first, real client appended
		"198.51.100.20, 203.0.113.7":                "198.51.100.20", // two trusted proxies in a row
		"garbage, 198.51.100.20":                    "198.51.100.20",
		"198.51.100.99, 198.51.100.20, 203.0.113.7": "198.51.100.20",
		"203.0.113.7":                               "203.0.113.10", // nothing untrusted: the direct peer
	}
	for xff, want := range cases {
		req := httptest.NewRequest("GET", "/api/v2/me", nil)
		req.RemoteAddr = "203.0.113.10:12345"
		req.Header.Set("X-Forwarded-For", xff)
		if got := middleware.ClientIP(req); got != want {
			t.Errorf("XFF %q: ClientIP() = %q, want %q", xff, got, want)
		}
	}
}

// One IPv6 subscriber holds a whole /64; keying limits on the full address would let it
// rotate through 2^64 addresses. IPv4-mapped IPv6 is the same client as plain IPv4.
func TestClientKey_GroupsIPv6ByPrefix(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)
	middleware.ResetTrustedProxiesForTesting()

	key := func(remote string) string {
		req := httptest.NewRequest("GET", "/api/v2/me", nil)
		req.RemoteAddr = remote
		return middleware.ClientKey(req)
	}
	if key("[2001:db8:1:2::1]:443") != key("[2001:db8:1:2:ffff:ffff:ffff:9]:443") {
		t.Error("two addresses in one IPv6 /64 got different rate-limit keys")
	}
	if key("[2001:db8:1:2::1]:443") == key("[2001:db8:1:3::1]:443") {
		t.Error("different IPv6 /64 prefixes share a rate-limit key")
	}
	if key("198.51.100.7:1") == key("198.51.100.8:1") {
		t.Error("different IPv4 addresses share a rate-limit key")
	}
	if key("[::ffff:198.51.100.7]:1") != key("198.51.100.7:1") {
		t.Error("IPv4-mapped IPv6 and IPv4 for the same client got different keys")
	}
}

// Behind the onion service every client arrives from tor, which gives each circuit its own
// address inside fc00:dead:beef:4dad::/64 (HiddenServiceExportCircuitID haproxy). Grouping
// that /64 like one subscriber's prefix would put every Tor user in a single bucket.
func TestClientKey_SeparatesTorCircuits(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)
	t.Setenv("TRUSTED_PROXIES", "203.0.113.0/24")
	middleware.ResetTrustedProxiesForTesting()
	t.Cleanup(middleware.ResetTrustedProxiesForTesting)

	viaProxy := func(client string) string {
		req := httptest.NewRequest("GET", "/api/v2/me", nil)
		req.RemoteAddr = "203.0.113.10:12345"
		req.Header.Set("X-Forwarded-For", client)
		return middleware.ClientKey(req)
	}
	circuit := viaProxy("fc00:dead:beef:4dad::1:2c3d")
	if circuit == viaProxy("fc00:dead:beef:4dad::1:2c3e") {
		t.Error("two Tor circuits share a rate-limit key")
	}
	if again := viaProxy("fc00:dead:beef:4dad::1:2c3d"); again != circuit {
		t.Error("one Tor circuit got two rate-limit keys")
	}
	// Only tor's own prefix is per-address; the neighbouring /64 is still one subscriber
	if viaProxy("fc00:dead:beef:4dae::1") != viaProxy("fc00:dead:beef:4dae::2") {
		t.Error("an ordinary IPv6 /64 is no longer grouped")
	}
}
