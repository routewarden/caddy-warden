package caddywarden_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/routewarden/caddy-warden"
)

func TestIPFilter_Unit(t *testing.T) {
	filter, err := caddywarden.NewIPFilter([]string{
		"192.168.1.10",
		"10.0.0.0/16",
		"2001:db8::/32",
	})
	if err != nil {
		t.Fatalf("unexpected error creating IPFilter: %v", err)
	}

	// 1. Exact IPv4 match in RemoteAddr
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.RemoteAddr = "192.168.1.10:1234"
	if !filter.IsAllowed(req1) {
		t.Errorf("expected 192.168.1.10 to be allowed")
	}

	// 2. CIDR subnet match in RemoteAddr
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "10.0.5.20:5678"
	if !filter.IsAllowed(req2) {
		t.Errorf("expected 10.0.5.20 in 10.0.0.0/16 to be allowed")
	}

	// 3. IPv6 CIDR subnet match in RemoteAddr
	req3 := httptest.NewRequest(http.MethodGet, "/", nil)
	req3.RemoteAddr = "[2001:db8::1]:5678"
	if !filter.IsAllowed(req3) {
		t.Errorf("expected 2001:db8::1 in 2001:db8::/32 to be allowed")
	}

	// 4. X-Forwarded-For header match
	req4 := httptest.NewRequest(http.MethodGet, "/", nil)
	req4.RemoteAddr = "203.0.113.1:80"
	req4.Header.Set("X-Forwarded-For", "192.168.1.10, 203.0.113.1")
	if !filter.IsAllowed(req4) {
		t.Errorf("expected X-Forwarded-For first IP to be allowed")
	}

	// 5. X-Real-IP header match
	req5 := httptest.NewRequest(http.MethodGet, "/", nil)
	req5.RemoteAddr = "203.0.113.1:80"
	req5.Header.Set("X-Real-IP", "10.0.99.1")
	if !filter.IsAllowed(req5) {
		t.Errorf("expected X-Real-IP to be allowed")
	}

	// 6. Non-whitelisted IP
	req6 := httptest.NewRequest(http.MethodGet, "/", nil)
	req6.RemoteAddr = "203.0.113.50:4321"
	if filter.IsAllowed(req6) {
		t.Errorf("expected 203.0.113.50 to NOT be allowed")
	}

	// 7. Malformed / empty client IP
	req7 := httptest.NewRequest(http.MethodGet, "/", nil)
	req7.RemoteAddr = "invalid-address"
	if filter.IsAllowed(req7) {
		t.Errorf("expected invalid address to NOT be allowed")
	}
}

func TestIPFilter_EmptyFilter(t *testing.T) {
	filter, err := caddywarden.NewIPFilter([]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	if filter.IsAllowed(req) {
		t.Errorf("empty filter should never match")
	}
}

func TestIPFilter_InvalidInputs(t *testing.T) {
	_, err := caddywarden.NewIPFilter([]string{"999.999.999.999"})
	if err == nil {
		t.Errorf("expected error for invalid IP address")
	}

	_, err2 := caddywarden.NewIPFilter([]string{"10.0.0.0/999"})
	if err2 == nil {
		t.Errorf("expected error for invalid CIDR subnet")
	}
}

func TestIPFilter_WhitespaceAndEmptyEntries(t *testing.T) {
	// Empty and whitespace-only entries should be cleanly ignored
	filter, err := caddywarden.NewIPFilter([]string{"", "  ", "\t", "192.168.1.100"})
	if err != nil {
		t.Fatalf("unexpected error creating filter with whitespace entries: %v", err)
	}

	reqAllowed := httptest.NewRequest(http.MethodGet, "/", nil)
	reqAllowed.RemoteAddr = "192.168.1.100:8080"
	if !filter.IsAllowed(reqAllowed) {
		t.Errorf("expected 192.168.1.100 to be allowed")
	}

	reqBlocked := httptest.NewRequest(http.MethodGet, "/", nil)
	reqBlocked.RemoteAddr = "192.168.1.101:8080"
	if filter.IsAllowed(reqBlocked) {
		t.Errorf("expected 192.168.1.101 to NOT be allowed")
	}
}

func TestIPFilter_UnparseableRemoteAddr(t *testing.T) {
	filter, err := caddywarden.NewIPFilter([]string{"10.0.0.1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// RemoteAddr has no port and is not valid IP
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.RemoteAddr = "not-an-ip"
	if filter.IsAllowed(req1) {
		t.Errorf("expected unparseable RemoteAddr to be rejected")
	}

	// RemoteAddr is empty string
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = ""
	if filter.IsAllowed(req2) {
		t.Errorf("expected empty RemoteAddr to be rejected")
	}
}

func TestIPFilter_MultiIPForwardedFor(t *testing.T) {
	filter, err := caddywarden.NewIPFilter([]string{"10.0.0.1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// X-Forwarded-For contains multiple IPs: client IP is first
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.RemoteAddr = "203.0.113.1:80"
	req1.Header.Set("X-Forwarded-For", "10.0.0.1, 192.168.1.1")
	if !filter.IsAllowed(req1) {
		t.Errorf("expected first IP in X-Forwarded-For to be allowed")
	}

	// X-Forwarded-For first IP (172.16.0.1) is NOT whitelisted
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "203.0.113.1:80"
	req2.Header.Set("X-Forwarded-For", "172.16.0.1, 10.0.0.1")
	if filter.IsAllowed(req2) {
		t.Errorf("expected first IP in X-Forwarded-For (not whitelisted) to be rejected")
	}
}

func TestIPFilter_PortAndBracketStripping(t *testing.T) {
	filter, err := caddywarden.NewIPFilter([]string{"192.168.1.50", "2001:db8::99"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 1. IPv4 with port in X-Forwarded-For
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.Header.Set("X-Forwarded-For", "192.168.1.50:49200, 10.0.0.1")
	if !filter.IsAllowed(req1) {
		t.Errorf("expected IPv4 with port in XFF to be stripped and allowed")
	}

	// 2. IPv6 with brackets and port in X-Forwarded-For
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("X-Forwarded-For", "[2001:db8::99]:55432")
	if !filter.IsAllowed(req2) {
		t.Errorf("expected bracketed IPv6 with port in XFF to be allowed")
	}

	// 3. IPv6 with brackets only in X-Real-IP
	req3 := httptest.NewRequest(http.MethodGet, "/", nil)
	req3.Header.Set("X-Real-IP", "[2001:db8::99]")
	if !filter.IsAllowed(req3) {
		t.Errorf("expected bracketed IPv6 in X-Real-IP to be allowed")
	}
}

