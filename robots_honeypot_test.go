package caddywarden_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	caddywarden "github.com/routewarden/caddy-warden"
)

func TestRobotsHoneypot_TokenGeneration(t *testing.T) {
	fixedTime := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)

	token1 := caddywarden.GetRobotsHoneypotToken("secret123", fixedTime)
	token2 := caddywarden.GetRobotsHoneypotToken("secret123", fixedTime)
	if token1 != token2 {
		t.Fatalf("expected deterministic token, got %q vs %q", token1, token2)
	}

	if len(token1) != 12 {
		t.Fatalf("expected 12-char token, got %q (len %d)", token1, len(token1))
	}

	tokenDiff := caddywarden.GetRobotsHoneypotToken("other-secret", fixedTime)
	if token1 == tokenDiff {
		t.Fatalf("expected different token for different secret, got %q", tokenDiff)
	}

	tokenDefault := caddywarden.GetRobotsHoneypotToken("", fixedTime)
	if tokenDefault == "" {
		t.Fatal("expected non-empty token for default secret")
	}

	nextDay := fixedTime.Add(24 * time.Hour)
	tokenNextDay := caddywarden.GetRobotsHoneypotToken("secret123", nextDay)
	if token1 == tokenNextDay {
		t.Fatalf("expected different token for next day, got %q", tokenNextDay)
	}
}

func TestRobotsHoneypot_ActiveTraps(t *testing.T) {
	fixedTime := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	activeTrap, validPrefixes := caddywarden.GetActiveRobotsHoneypotTraps("mysecret", fixedTime)

	if !strings.HasPrefix(activeTrap, "/_rw_trap_") || !strings.HasSuffix(activeTrap, "/") {
		t.Fatalf("unexpected activeTrap format: %q", activeTrap)
	}

	if len(validPrefixes) != 2 {
		t.Fatalf("expected 2 active prefixes, got %d", len(validPrefixes))
	}

	todayToken := caddywarden.GetRobotsHoneypotToken("mysecret", fixedTime)
	yesterdayToken := caddywarden.GetRobotsHoneypotToken("mysecret", fixedTime.Add(-24*time.Hour))

	expectedTodayPrefix := "/_rw_trap_" + todayToken
	expectedYesterdayPrefix := "/_rw_trap_" + yesterdayToken

	if validPrefixes[0] != expectedTodayPrefix || validPrefixes[1] != expectedYesterdayPrefix {
		t.Fatalf("unexpected validPrefixes: %v", validPrefixes)
	}
}

func TestRobotsHoneypot_IsRobotsTxtPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/robots.txt", true},
		{"/robots.txt/", true},
		{"/ROBOTS.TXT", true},
		{" /robots.txt ", true},
		{"/robots.txt.bak", false},
		{"/api/robots.txt", false},
		{"/", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := caddywarden.IsRobotsTxtPath(tt.path); got != tt.want {
			t.Errorf("IsRobotsTxtPath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestRobotsHoneypot_InjectRobotsTxtTrap(t *testing.T) {
	activeTrap := "/_rw_trap_f8a3e9c1/"

	// Case 1: Empty upstream body
	injectedEmpty := string(caddywarden.InjectRobotsTxtTrap(nil, activeTrap))
	if !strings.Contains(injectedEmpty, "User-agent: *\nDisallow: /_rw_trap_f8a3e9c1/\n") {
		t.Fatalf("unexpected empty injection: %q", injectedEmpty)
	}

	// Case 2: Existing upstream body without trailing newline
	origBody := "User-agent: Googlebot\nDisallow: /admin"
	injected := string(caddywarden.InjectRobotsTxtTrap([]byte(origBody), activeTrap))
	if !strings.HasPrefix(injected, origBody) {
		t.Fatalf("original body was not preserved: %q", injected)
	}
	if !strings.Contains(injected, "\nDisallow: /_rw_trap_f8a3e9c1/\n") {
		t.Fatalf("missing injected disallow: %q", injected)
	}
}

func TestRobotsHoneypot_MiddlewareInterceptionAndBanning(t *testing.T) {
	upstream := caddyhttp.HandlerFunc(func(w http.ResponseWriter, req *http.Request) error {
		if req.URL.Path == "/robots.txt" {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /private\n"))
			return nil
		}
		if req.URL.Path == "/normal.html" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))
			return nil
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("Not Found"))
		return nil
	})

	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
	rw := &caddywarden.RouteWarden{
		Enabled:                 true,
		EnableRobotsTxtHoneypot: true,
		RobotsTxtHoneypotSecret: "caddy-test-secret",
		TrapBanDuration:         "1h",
	}

	if err := rw.Provision(ctx); err != nil {
		t.Fatalf("failed to provision RouteWarden: %v", err)
	}

	now := time.Now()
	activeTrap, validPrefixes := caddywarden.GetActiveRobotsHoneypotTraps(rw.RobotsTxtHoneypotSecret, now)

	// 1. GET /robots.txt -> Upstream content preserved AND dynamic trap injected
	reqRobots := httptest.NewRequest(http.MethodGet, "http://example.com/robots.txt", nil)
	reqRobots.RemoteAddr = "198.51.100.10:1234"
	recRobots := httptest.NewRecorder()
	if err := rw.ServeHTTP(recRobots, reqRobots, upstream); err != nil {
		t.Fatalf("ServeHTTP error: %v", err)
	}

	if recRobots.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /robots.txt, got %d", recRobots.Code)
	}
	body := recRobots.Body.String()
	if !strings.Contains(body, "Disallow: /private") {
		t.Fatalf("expected upstream content to be preserved, got %q", body)
	}
	if !strings.Contains(body, "Disallow: "+activeTrap) {
		t.Fatalf("expected injected active trap %q in body, got %q", activeTrap, body)
	}

	// 2. Crawler requests today's trap URI -> Blocked with 403 and client IP banned
	crawlerIP := "198.51.100.88"
	reqTrap := httptest.NewRequest(http.MethodGet, "http://example.com"+validPrefixes[0]+"/sub/target.html", nil)
	reqTrap.RemoteAddr = crawlerIP + ":5678"
	recTrap := httptest.NewRecorder()
	if err := rw.ServeHTTP(recTrap, reqTrap, upstream); err != nil {
		t.Fatalf("ServeHTTP error: %v", err)
	}

	if recTrap.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for honeypot trap, got %d", recTrap.Code)
	}

	// 3. Crawler subsequent request to legitimate /normal.html -> Blocked due to active ban
	reqSubsequent := httptest.NewRequest(http.MethodGet, "http://example.com/normal.html", nil)
	reqSubsequent.RemoteAddr = crawlerIP + ":5678"
	recSubsequent := httptest.NewRecorder()
	if err := rw.ServeHTTP(recSubsequent, reqSubsequent, upstream); err != nil {
		t.Fatalf("ServeHTTP error: %v", err)
	}

	if recSubsequent.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for banned client on normal route, got %d", recSubsequent.Code)
	}

	// 4. Request from another IP to yesterday's rollover trap prefix -> Also blocked and banned
	otherCrawlerIP := "198.51.100.99"
	reqYesterday := httptest.NewRequest(http.MethodGet, "http://example.com"+validPrefixes[1]+"/", nil)
	reqYesterday.RemoteAddr = otherCrawlerIP + ":9999"
	recYesterday := httptest.NewRecorder()
	if err := rw.ServeHTTP(recYesterday, reqYesterday, upstream); err != nil {
		t.Fatalf("ServeHTTP error: %v", err)
	}

	if recYesterday.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for yesterday's trap prefix, got %d", recYesterday.Code)
	}

	// 5. Clean client request to /normal.html -> 200 OK
	reqClean := httptest.NewRequest(http.MethodGet, "http://example.com/normal.html", nil)
	reqClean.RemoteAddr = "203.0.113.50:4321"
	recClean := httptest.NewRecorder()
	if err := rw.ServeHTTP(recClean, reqClean, upstream); err != nil {
		t.Fatalf("ServeHTTP error: %v", err)
	}

	if recClean.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for clean client, got %d", recClean.Code)
	}
}

func TestRobotsHoneypot_Upstream404Fallback(t *testing.T) {
	upstream := caddyhttp.HandlerFunc(func(w http.ResponseWriter, req *http.Request) error {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("Not Found"))
		return nil
	})

	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
	rw := &caddywarden.RouteWarden{
		Enabled:                 true,
		EnableRobotsTxtHoneypot: true,
		RobotsTxtHoneypotSecret: "fallback-secret",
	}

	if err := rw.Provision(ctx); err != nil {
		t.Fatalf("failed to provision RouteWarden: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/robots.txt", nil)
	rec := httptest.NewRecorder()
	if err := rw.ServeHTTP(rec, req, upstream); err != nil {
		t.Fatalf("ServeHTTP error: %v", err)
	}

	// Should synthesize a 200 OK robots.txt
	if rec.Code != http.StatusOK {
		t.Fatalf("expected synthesized 200 OK when upstream 404s, got %d", rec.Code)
	}
	body := rec.Body.String()
	activeTrap, _ := caddywarden.GetActiveRobotsHoneypotTraps(rw.RobotsTxtHoneypotSecret, time.Now())
	if !strings.Contains(body, "Disallow: "+activeTrap) {
		t.Fatalf("expected synthesized robots.txt to contain trap %q, got %q", activeTrap, body)
	}
}

func TestRobotsHoneypot_CaddyfileParsing(t *testing.T) {
	d := caddyfile.NewTestDispenser(`
		route_warden {
			enable_robots_txt_honeypot true
			robots_txt_honeypot_secret custom-secret-123
		}
	`)

	rw := &caddywarden.RouteWarden{}
	if err := rw.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("unexpected UnmarshalCaddyfile error: %v", err)
	}

	if !rw.EnableRobotsTxtHoneypot {
		t.Errorf("expected EnableRobotsTxtHoneypot=true, got %v", rw.EnableRobotsTxtHoneypot)
	}
	if rw.RobotsTxtHoneypotSecret != "custom-secret-123" {
		t.Errorf("expected RobotsTxtHoneypotSecret='custom-secret-123', got %q", rw.RobotsTxtHoneypotSecret)
	}
}
