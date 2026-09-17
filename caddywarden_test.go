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
