package caddywarden_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	caddywarden "github.com/routewarden/caddy-warden"
)

func TestRouteWarden_ModuleInfo(t *testing.T) {
	rw := caddywarden.RouteWarden{}
	info := rw.CaddyModule()
	if info.ID != "http.handlers.routewarden" {
		t.Errorf("unexpected module ID: %s", info.ID)
	}
	mod := info.New()
	if _, ok := mod.(*caddywarden.RouteWarden); !ok {
		t.Fatalf("expected *RouteWarden instance from New()")
	}
}

func TestRouteWarden_Validate(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		shouldErr  bool
	}{
		{"valid default zero", 0, false},
		{"valid 403", 403, false},
		{"valid 200", 200, false},
		{"invalid low status", 99, true},
		{"invalid high status", 600, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rw := &caddywarden.RouteWarden{
				Response: &caddywarden.ResponseConfig{
					StatusCode: tc.statusCode,
				},
			}
			err := rw.Validate()
			if tc.shouldErr && err == nil {
				t.Errorf("expected error for status %d, got nil", tc.statusCode)
			}
			if !tc.shouldErr && err != nil {
				t.Errorf("unexpected error for status %d: %v", tc.statusCode, err)
			}
		})
	}

	// Also validate when rw.Response is nil
	rwNilResp := &caddywarden.RouteWarden{Response: nil}
	if err := rwNilResp.Validate(); err != nil {
		t.Errorf("unexpected error when Response is nil: %v", err)
	}
}

func TestRouteWarden_ProvisionErrors(t *testing.T) {
	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})

	// Invalid block pattern regex
	rwInvalidBlock := &caddywarden.RouteWarden{
		PathPatterns: []string{"[unclosed"},
	}
	if err := rwInvalidBlock.Provision(ctx); err == nil {
		t.Error("expected error for invalid block regex, got nil")
	}

	// Invalid allow pattern regex
	rwInvalidAllow := &caddywarden.RouteWarden{
		AllowPatterns: []string{"(?P<invalid"},
	}
	if err := rwInvalidAllow.Provision(ctx); err == nil {
		t.Error("expected error for invalid allow regex, got nil")
	}

	// Invalid allowed_ips
	rwInvalidIP := &caddywarden.RouteWarden{
		AllowedIPs: []string{"not-an-ip-or-cidr"},
	}
	if err := rwInvalidIP.Provision(ctx); err == nil {
		t.Error("expected error for invalid allowed_ips, got nil")
	}

	// Invalid response config (e.g. invalid captcha template)
	rwInvalidResp := &caddywarden.RouteWarden{
		Response: &caddywarden.ResponseConfig{
			Mode: "captcha",
			Captcha: &caddywarden.CaptchaConfig{
				Template: "{{ .Unclosed",
			},
		},
	}
	if err := rwInvalidResp.Provision(ctx); err == nil {
		t.Error("expected error for invalid captcha template, got nil")
	}
}

func TestRouteWarden_ServeHTTP_Disabled(t *testing.T) {
	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
	rw := &caddywarden.RouteWarden{
		Enabled: false,
	}
	if err := rw.Provision(ctx); err != nil {
		t.Fatalf("unexpected provision error: %v", err)
	}

	next := &testHandler{}
	req := httptest.NewRequest(http.MethodGet, "/.env", nil)
	rec := httptest.NewRecorder()

	err := rw.ServeHTTP(rec, req, next)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !next.handled {
		t.Error("expected downstream handler to be called when disabled")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200 when disabled, got %d", rec.Code)
	}
}

func TestRouteWarden_ServeHTTP_AllowPatterns(t *testing.T) {
	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
	rw := &caddywarden.RouteWarden{
		Enabled:                    true,
		EnableDefaultPatterns:      true,
		EnableDefaultAllowPatterns: true,
		AllowPatterns:              []string{`(?i)^/api/webhook/config\.json$`},
	}
	if err := rw.Provision(ctx); err != nil {
		t.Fatalf("unexpected provision error: %v", err)
	}

	// 1. Default allow pattern: /robots.txt (which ends in .txt and would otherwise be blocked)
	next := &testHandler{}
	req := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
	rec := httptest.NewRecorder()
	if err := rw.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !next.handled {
		t.Error("expected /robots.txt to be allowed via default allow pattern")
	}

	// 2. Default allow pattern: /.well-known/acme-challenge/test
	next2 := &testHandler{}
	req2 := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/test", nil)
	rec2 := httptest.NewRecorder()
	if err := rw.ServeHTTP(rec2, req2, next2); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !next2.handled {
		t.Error("expected /.well-known to be allowed via default allow pattern")
	}

	// 3. Custom allow pattern: /api/webhook/config.json
	next3 := &testHandler{}
	req3 := httptest.NewRequest(http.MethodGet, "/api/webhook/config.json", nil)
	rec3 := httptest.NewRecorder()
	if err := rw.ServeHTTP(rec3, req3, next3); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !next3.handled {
		t.Error("expected custom allow pattern to pass downstream")
	}
}

func TestRouteWarden_ServeHTTP_CheckQuery(t *testing.T) {
	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
	rw := &caddywarden.RouteWarden{
		Enabled:                    true,
		EnableDefaultPatterns:      true,
		EnableDefaultAllowPatterns: true,
		CheckQuery:                 true,
		Response: &caddywarden.ResponseConfig{
			Mode:       "json",
			StatusCode: 403,
		},
	}
	if err := rw.Provision(ctx); err != nil {
		t.Fatalf("unexpected provision error: %v", err)
	}

	// Query string containing sensitive file (.env)
	next := &testHandler{}
	req := httptest.NewRequest(http.MethodGet, "/download?file=.env", nil)
	rec := httptest.NewRecorder()

	if err := rw.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if next.handled {
		t.Error("expected request with sensitive query to be blocked")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", rec.Code)
	}

	// URL-encoded query string containing sensitive file (%2eenv)
	next2 := &testHandler{}
	req2 := httptest.NewRequest(http.MethodGet, "/view?path=%2eenv", nil)
	rec2 := httptest.NewRecorder()

	if err := rw.ServeHTTP(rec2, req2, next2); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if next2.handled {
		t.Error("expected request with URL-encoded sensitive query to be blocked")
	}
	if rec2.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", rec2.Code)
	}

	// Benign query string
	next3 := &testHandler{}
	req3 := httptest.NewRequest(http.MethodGet, "/search?q=gophers", nil)
	rec3 := httptest.NewRecorder()

	if err := rw.ServeHTTP(rec3, req3, next3); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !next3.handled {
		t.Error("expected request with benign query to pass downstream")
	}
	if rec3.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec3.Code)
	}
}


func TestRouteWarden_ServeHTTP_Methods(t *testing.T) {
	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})

	t.Run("Default inspects only GET", func(t *testing.T) {
		rw := &caddywarden.RouteWarden{
			Enabled:               true,
			EnableDefaultPatterns: true,
		}
		if err := rw.Provision(ctx); err != nil {
			t.Fatalf("unexpected provision error: %v", err)
		}

		// GET /.env should be blocked
		next1 := &testHandler{}
		reqGet := httptest.NewRequest(http.MethodGet, "/.env", nil)
		recGet := httptest.NewRecorder()
		if err := rw.ServeHTTP(recGet, reqGet, next1); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if next1.handled || recGet.Code != http.StatusForbidden {
			t.Errorf("expected GET /.env to be blocked with 403, got handled=%v code=%d", next1.handled, recGet.Code)
		}

		// POST /.env should bypass inspection and reach downstream handler
		next2 := &testHandler{}
		reqPost := httptest.NewRequest(http.MethodPost, "/.env", nil)
		recPost := httptest.NewRecorder()
		if err := rw.ServeHTTP(recPost, reqPost, next2); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !next2.handled || recPost.Code != http.StatusOK {
			t.Errorf("expected POST /.env to pass downstream, got handled=%v code=%d", next2.handled, recPost.Code)
		}

		// PUT, DELETE, PATCH should also bypass
		for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodHead} {
			next := &testHandler{}
			req := httptest.NewRequest(method, "/.env", nil)
			rec := httptest.NewRecorder()
			if err := rw.ServeHTTP(rec, req, next); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !next.handled || rec.Code != http.StatusOK {
				t.Errorf("expected %s /.env to pass downstream", method)
			}
		}
	})

	t.Run("Custom methods GET and POST", func(t *testing.T) {
		rw := &caddywarden.RouteWarden{
			Enabled:               true,
			EnableDefaultPatterns: true,
			Methods:               []string{"GET", "POST"},
		}
		if err := rw.Provision(ctx); err != nil {
			t.Fatalf("unexpected provision error: %v", err)
		}

		for _, method := range []string{http.MethodGet, http.MethodPost} {
			next := &testHandler{}
			req := httptest.NewRequest(method, "/.env", nil)
			rec := httptest.NewRecorder()
			if err := rw.ServeHTTP(rec, req, next); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if next.handled || rec.Code != http.StatusForbidden {
				t.Errorf("expected %s /.env to be blocked with 403", method)
			}
		}

		// DELETE should bypass
		nextDel := &testHandler{}
		reqDel := httptest.NewRequest(http.MethodDelete, "/.env", nil)
		recDel := httptest.NewRecorder()
		if err := rw.ServeHTTP(recDel, reqDel, nextDel); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !nextDel.handled || recDel.Code != http.StatusOK {
			t.Errorf("expected DELETE /.env to pass downstream")
		}
	})

	t.Run("Case-insensitive and empty fallback", func(t *testing.T) {
		rw := &caddywarden.RouteWarden{
			Enabled:               true,
			EnableDefaultPatterns: true,
			Methods:               []string{"post", "delete"},
		}
		if err := rw.Provision(ctx); err != nil {
			t.Fatalf("unexpected provision error: %v", err)
		}

		// POST should be blocked
		nextPost := &testHandler{}
		reqPost := httptest.NewRequest(http.MethodPost, "/.env", nil)
		recPost := httptest.NewRecorder()
		if err := rw.ServeHTTP(recPost, reqPost, nextPost); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if nextPost.handled || recPost.Code != http.StatusForbidden {
			t.Errorf("expected POST /.env to be blocked with 403")
		}

		// GET should bypass
		nextGet := &testHandler{}
		reqGet := httptest.NewRequest(http.MethodGet, "/.env", nil)
		recGet := httptest.NewRecorder()
		if err := rw.ServeHTTP(recGet, reqGet, nextGet); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !nextGet.handled || recGet.Code != http.StatusOK {
			t.Errorf("expected GET /.env to pass downstream")
		}
	})
}
