package caddywarden_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	caddywarden "github.com/routewarden/caddy-warden"
)

// Dummy next handler in Caddy middleware chain
type testHandler struct {
	handled bool
}

func (th *testHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	th.handled = true
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Hello Upstream"))
	return nil
}

func TestCaddyfile_ParsingAndMiddleware(t *testing.T) {
	caddyfileInput := `
	routewarden {
		allowed_ips 10.0.0.1
		path_patterns (?i)^/admin/secret$
		check_query
		response {
			mode json
			status 403
			body "{\"error\":\"Access Blocked\"}"
		}
	}
	`

	d := caddyfile.NewTestDispenser(caddyfileInput)
	rw := &caddywarden.RouteWarden{}
	err := rw.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("failed to unmarshal caddyfile: %v", err)
	}

	// Provision with valid root context
	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
	if err := rw.Provision(ctx); err != nil {
		t.Fatalf("failed to provision routewarden module: %v", err)
	}

	// Test 1: Normal path passes downstream
	next := &testHandler{}
	req := httptest.NewRequest(http.MethodGet, "/public/index.html", nil)
	rec := httptest.NewRecorder()

	err = rw.ServeHTTP(rec, req, next)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !next.handled {
		t.Error("expected downstream handler to be called")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	// Test 2: Sensitive endpoint blocked (.env)
	next2 := &testHandler{}
	req2 := httptest.NewRequest(http.MethodGet, "/.env", nil)
	rec2 := httptest.NewRecorder()

	err = rw.ServeHTTP(rec2, req2, next2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if next2.handled {
		t.Error("expected downstream handler NOT to be called for .env")
	}
	if rec2.Code != http.StatusForbidden {
		t.Errorf("expected status 403 for .env, got %d", rec2.Code)
	}

	// Test 3: Anti-evasion double encoding blocked (%252e%252e/.env)
	next3 := &testHandler{}
	req3 := httptest.NewRequest(http.MethodGet, "/%252e%252e/.env", nil)
	rec3 := httptest.NewRecorder()

	err = rw.ServeHTTP(rec3, req3, next3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if next3.handled {
		t.Error("expected downstream handler NOT to be called for evasion path")
	}
	if rec3.Code != http.StatusForbidden {
		t.Errorf("expected status 403 for evasion path, got %d", rec3.Code)
	}

	// Test 4: Custom path pattern blocked (/admin/secret)
	next4 := &testHandler{}
	req4 := httptest.NewRequest(http.MethodGet, "/admin/secret", nil)
	rec4 := httptest.NewRecorder()

	err = rw.ServeHTTP(rec4, req4, next4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if next4.handled {
		t.Error("expected downstream handler NOT to be called for /admin/secret")
	}
	if rec4.Code != http.StatusForbidden {
		t.Errorf("expected status 403 for /admin/secret, got %d", rec4.Code)
	}

	// Test 5: Whitelisted IP bypasses block
	next5 := &testHandler{}
	req5 := httptest.NewRequest(http.MethodGet, "/.env", nil)
	req5.RemoteAddr = "10.0.0.1:12345"
	rec5 := httptest.NewRecorder()

	err = rw.ServeHTTP(rec5, req5, next5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !next5.handled {
		t.Error("expected whitelisted IP to bypass block and call downstream handler")
	}
	if rec5.Code != http.StatusOK {
		t.Errorf("expected status 200 for whitelisted IP, got %d", rec5.Code)
	}
}
