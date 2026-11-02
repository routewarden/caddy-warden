package caddywarden

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestPoW_ChallengeAndVerification(t *testing.T) {
	clientIP := "198.51.100.33"
	secret := "caddy-pow-test-secret"
	difficulty := 10
	now := time.Now()

	challenge, err := GeneratePoWChallenge(clientIP, secret, difficulty, now)
	if err != nil {
		t.Fatalf("GeneratePoWChallenge failed: %v", err)
	}

	nonce := SolvePoW(challenge, difficulty)
	solution := fmt.Sprintf("%s.%d", challenge, nonce)

	valid, reason := VerifyPoWSolution(clientIP, secret, solution, 300, now.Add(5*time.Second))
	if !valid {
		t.Fatalf("expected solution to verify, failed: %s", reason)
	}

	// Mismatched IP
	valid, _ = VerifyPoWSolution("203.0.113.1", secret, solution, 300, now.Add(5*time.Second))
	if valid {
		t.Errorf("expected IP mismatch to fail verification")
	}

	// Expired
	valid, _ = VerifyPoWSolution(clientIP, secret, solution, 300, now.Add(305*time.Second))
	if valid {
		t.Errorf("expected expired challenge to fail verification")
	}
}

func TestPoW_CaddyHandlerBypass(t *testing.T) {
	clientIP := "192.0.2.77"
	secret := "caddy-middleware-secret"
	difficulty := 10

	rw := &RouteWarden{
		Enabled:           true,
		BlockUserAgents:   []string{"^ScraperBot.*"},
		BlockPatterns:     []string{"^/admin.*"},
		HoneypotTrapPaths: []string{"/caddy_trap"},
		Response: &ResponseConfig{
			Mode:              "powChallenge",
			PoWDifficulty:     difficulty,
			PoWSecret:         secret,
			PoWTimeoutSeconds: 300,
		},
	}

	if err := rw.Provision(caddy.Context{}); err != nil {
		t.Fatalf("failed to provision middleware: %v", err)
	}

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("CADDY_GRANTED"))
		return nil
	})

	// 1. ScraperBot without PoW -> 429 Too Many Requests
	req1 := httptest.NewRequest(http.MethodGet, "/index.html", nil)
	req1.RemoteAddr = clientIP + ":34567"
	req1.Header.Set("User-Agent", "ScraperBot/1.0")
	rec1 := httptest.NewRecorder()

	_ = rw.ServeHTTP(rec1, req1, next)
	if rec1.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 Too Many Requests, got %d", rec1.Code)
	}
	if !strings.Contains(rec1.Body.String(), "__rw_pow") {
		t.Fatalf("expected PoW challenge HTML in response body")
	}

	// 2. Solve challenge for clientIP
	challenge, err := GeneratePoWChallenge(clientIP, secret, difficulty, time.Now())
	if err != nil {
		t.Fatalf("failed to generate challenge: %v", err)
	}
	nonce := SolvePoW(challenge, difficulty)
	solution := fmt.Sprintf("%s.%d", challenge, nonce)

	// 3. Request with ScraperBot + __rw_pow cookie -> 200 CADDY_GRANTED
	req2 := httptest.NewRequest(http.MethodGet, "/index.html", nil)
	req2.RemoteAddr = clientIP + ":34567"
	req2.Header.Set("User-Agent", "ScraperBot/1.0")
	req2.AddCookie(&http.Cookie{Name: "__rw_pow", Value: solution})
	rec2 := httptest.NewRecorder()

	_ = rw.ServeHTTP(rec2, req2, next)
	if rec2.Code != http.StatusOK || rec2.Body.String() != "CADDY_GRANTED" {
		t.Fatalf("expected 200 CADDY_GRANTED with valid PoW cookie, got %d (%s)", rec2.Code, rec2.Body.String())
	}

	// 4. Request with X-RW-PoW header -> 200 CADDY_GRANTED
	req3 := httptest.NewRequest(http.MethodGet, "/admin/system", nil)
	req3.RemoteAddr = clientIP + ":34567"
	req3.Header.Set("X-RW-PoW", solution)
	rec3 := httptest.NewRecorder()

	_ = rw.ServeHTTP(rec3, req3, next)
	if rec3.Code != http.StatusOK || rec3.Body.String() != "CADDY_GRANTED" {
		t.Fatalf("expected 200 CADDY_GRANTED for /admin with valid PoW header, got %d", rec3.Code)
	}

	// 5. Honeypot trap cannot be bypassed by PoW
	reqTrap := httptest.NewRequest(http.MethodGet, "/caddy_trap/spider", nil)
	reqTrap.RemoteAddr = clientIP + ":34567"
	reqTrap.AddCookie(&http.Cookie{Name: "__rw_pow", Value: solution})
	recTrap := httptest.NewRecorder()

	_ = rw.ServeHTTP(recTrap, reqTrap, next)
	if recTrap.Code == http.StatusOK {
		t.Fatalf("expected honeypot trap to trigger and block despite valid PoW")
	}
}
