package caddywarden_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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

	// Validate top-level StatusCode
	rwTopInvalid := &caddywarden.RouteWarden{StatusCode: 999}
	if err := rwTopInvalid.Validate(); err == nil {
		t.Errorf("expected error for invalid top-level StatusCode 999, got nil")
	}
	rwTopValid := &caddywarden.RouteWarden{StatusCode: 403}
	if err := rwTopValid.Validate(); err != nil {
		t.Errorf("unexpected error for valid top-level StatusCode 403: %v", err)
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

	t.Run("Allowlist supersedes both default and custom block patterns", func(t *testing.T) {
		rw := &caddywarden.RouteWarden{
			Enabled:                    true,
			EnableDefaultPatterns:      true,
			EnableDefaultAllowPatterns: true,
			BlockPatterns:              []string{`(?i)^/api/.*$`},
			AllowPatterns: []string{
				`(?i)^/api/public/.*\.env$`,
				`(?i)^/public/.*\.txt$`,
			},
		}
		if err := rw.Provision(ctx); err != nil {
			t.Fatalf("unexpected provision error: %v", err)
		}

		// 1. Default allow pattern: /robots.txt
		// (/robots.txt matches default block pattern for .txt, but is exempted by default allow pattern)
		nextRobots := &testHandler{}
		reqRobots := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
		recRobots := httptest.NewRecorder()
		if err := rw.ServeHTTP(recRobots, reqRobots, nextRobots); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !nextRobots.handled || recRobots.Code != http.StatusOK {
			t.Error("expected /robots.txt to pass through via default allowlist override")
		}

		// 2. Default allow pattern: /.well-known/acme-challenge/test
		// (/.well-known matches hidden directory block pattern, but acme-challenge is allowed)
		nextAcme := &testHandler{}
		reqAcme := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/test", nil)
		recAcme := httptest.NewRecorder()
		if err := rw.ServeHTTP(recAcme, reqAcme, nextAcme); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !nextAcme.handled || recAcme.Code != http.StatusOK {
			t.Error("expected /.well-known/acme-challenge to pass through via default allowlist override")
		}

		// 3. Custom allow overriding default block (.env)
		// /api/public/demo.env matches default .env block pattern, but matches custom allow pattern
		nextEnv := &testHandler{}
		reqEnv := httptest.NewRequest(http.MethodGet, "/api/public/demo.env", nil)
		recEnv := httptest.NewRecorder()
		if err := rw.ServeHTTP(recEnv, reqEnv, nextEnv); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !nextEnv.handled || recEnv.Code != http.StatusOK {
			t.Error("expected /api/public/demo.env to supersede blocklist and pass through")
		}

		// 4. Custom allow overriding custom block pattern (/api/.*)
		// /public/info.txt matches block pattern for .txt, but matches custom allow pattern
		nextTxt := &testHandler{}
		reqTxt := httptest.NewRequest(http.MethodGet, "/public/info.txt", nil)
		recTxt := httptest.NewRecorder()
		if err := rw.ServeHTTP(recTxt, reqTxt, nextTxt); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !nextTxt.handled || recTxt.Code != http.StatusOK {
			t.Error("expected /public/info.txt to supersede blocklist and pass through")
		}

		// 5. Normal blocked request (not in allowlist) should be rejected
		nextBlocked := &testHandler{}
		reqBlocked := httptest.NewRequest(http.MethodGet, "/api/private/secret.env", nil)
		recBlocked := httptest.NewRecorder()
		if err := rw.ServeHTTP(recBlocked, reqBlocked, nextBlocked); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if nextBlocked.handled || recBlocked.Code != http.StatusForbidden {
			t.Errorf("expected /api/private/secret.env to be blocked with 403, got %d", recBlocked.Code)
		}
	})

	t.Run("Disabling default allow patterns removes exemption", func(t *testing.T) {
		rw := &caddywarden.RouteWarden{
			Enabled:                    true,
			EnableDefaultPatterns:      true,
			EnableDefaultAllowPatterns: false,
		}
		if err := rw.Provision(ctx); err != nil {
			t.Fatalf("unexpected provision error: %v", err)
		}

		// When default allow patterns are disabled, /robots.txt matches the default .txt block rule
		nextRobots := &testHandler{}
		reqRobots := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
		recRobots := httptest.NewRecorder()
		if err := rw.ServeHTTP(recRobots, reqRobots, nextRobots); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if nextRobots.handled || recRobots.Code != http.StatusForbidden {
			t.Errorf("expected /robots.txt to be blocked when EnableDefaultAllowPatterns is false, got %d", recRobots.Code)
		}
	})
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

func TestRouteWarden_CheckQuery_EdgeCases(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	rw := &caddywarden.RouteWarden{
		Enabled:               true,
		EnableDefaultPatterns: true,
		CheckQuery:            true,
	}
	if err := rw.Provision(ctx); err != nil {
		t.Fatalf("unexpected provision error: %v", err)
	}

	t.Run("Multi-value query parameter with sensitive value", func(t *testing.T) {
		next := &testHandler{}
		req := httptest.NewRequest(http.MethodGet, "/search?file=report&file=backup.sql", nil)
		rec := httptest.NewRecorder()
		if err := rw.ServeHTTP(rec, req, next); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if next.handled || rec.Code != http.StatusForbidden {
			t.Errorf("expected 403 for query containing backup.sql, got %d", rec.Code)
		}
	})

	t.Run("Malformed percent-encoding in query", func(t *testing.T) {
		next := &testHandler{}
		req := httptest.NewRequest(http.MethodGet, "/search?file=%ZZ/.env", nil)
		rec := httptest.NewRecorder()
		if err := rw.ServeHTTP(rec, req, next); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if next.handled || rec.Code != http.StatusForbidden {
			t.Errorf("expected 403 for malformed encoding containing .env, got %d", rec.Code)
		}
	})

	t.Run("Benign query string does not trigger block", func(t *testing.T) {
		next := &testHandler{}
		req := httptest.NewRequest(http.MethodGet, "/search?page=1&limit=20&sort=name", nil)
		rec := httptest.NewRecorder()
		if err := rw.ServeHTTP(rec, req, next); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !next.handled || rec.Code != http.StatusOK {
			t.Errorf("expected 200 for benign query, got %d", rec.Code)
		}
	})

	t.Run("Empty query string with checkQuery enabled", func(t *testing.T) {
		next := &testHandler{}
		req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
		rec := httptest.NewRecorder()
		if err := rw.ServeHTTP(rec, req, next); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !next.handled || rec.Code != http.StatusOK {
			t.Errorf("expected 200 for no query string, got %d", rec.Code)
		}
	})

	t.Run("Query parameter key matches sensitive pattern", func(t *testing.T) {
		next := &testHandler{}
		req := httptest.NewRequest(http.MethodGet, "/search?foo=bar&.env=1", nil)
		rec := httptest.NewRecorder()
		if err := rw.ServeHTTP(rec, req, next); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if next.handled || rec.Code != http.StatusForbidden {
			t.Errorf("expected 403 when query key is .env, got %d", rec.Code)
		}
	})

	t.Run("Query parameter value with path traversal", func(t *testing.T) {
		next := &testHandler{}
		req := httptest.NewRequest(http.MethodGet, "/search?file=/images/../.env", nil)
		rec := httptest.NewRecorder()
		if err := rw.ServeHTTP(rec, req, next); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if next.handled || rec.Code != http.StatusForbidden {
			t.Errorf("expected 403 when query value normalizes to .env, got %d", rec.Code)
		}
	})
}

func TestRouteWarden_Methods_WithCheckQuery(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	rw := &caddywarden.RouteWarden{
		Enabled:               true,
		EnableDefaultPatterns: true,
		CheckQuery:            true,
		Methods:               []string{"GET", "POST"},
	}
	if err := rw.Provision(ctx); err != nil {
		t.Fatalf("unexpected provision error: %v", err)
	}

	t.Run("POST with sensitive query is blocked when POST in methods", func(t *testing.T) {
		next := &testHandler{}
		req := httptest.NewRequest(http.MethodPost, "/submit?file=.env", nil)
		rec := httptest.NewRecorder()
		if err := rw.ServeHTTP(rec, req, next); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if next.handled || rec.Code != http.StatusForbidden {
			t.Errorf("expected 403 for POST with sensitive query, got %d", rec.Code)
		}
	})

	t.Run("DELETE with sensitive query bypasses when DELETE not in methods", func(t *testing.T) {
		next := &testHandler{}
		req := httptest.NewRequest(http.MethodDelete, "/submit?file=.env", nil)
		rec := httptest.NewRecorder()
		if err := rw.ServeHTTP(rec, req, next); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !next.handled || rec.Code != http.StatusOK {
			t.Errorf("expected 200 for DELETE bypassing inspection, got %d", rec.Code)
		}
	})
}

func TestRouteWarden_Methods_WhitespacePadded(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	rw := &caddywarden.RouteWarden{
		Enabled:               true,
		EnableDefaultPatterns: true,
		Methods:               []string{"  get  ", "  post  "},
	}
	if err := rw.Provision(ctx); err != nil {
		t.Fatalf("unexpected provision error: %v", err)
	}

	// GET should be inspected and blocked
	nextGet := &testHandler{}
	reqGet := httptest.NewRequest(http.MethodGet, "/.env", nil)
	recGet := httptest.NewRecorder()
	if err := rw.ServeHTTP(recGet, reqGet, nextGet); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if nextGet.handled || recGet.Code != http.StatusForbidden {
		t.Errorf("expected trimmed ' get ' to match GET and block /.env, got %d", recGet.Code)
	}

	// POST should be inspected and blocked
	nextPost := &testHandler{}
	reqPost := httptest.NewRequest(http.MethodPost, "/.env", nil)
	recPost := httptest.NewRecorder()
	if err := rw.ServeHTTP(recPost, reqPost, nextPost); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if nextPost.handled || recPost.Code != http.StatusForbidden {
		t.Errorf("expected trimmed ' post ' to match POST and block /.env, got %d", recPost.Code)
	}

	// PUT should bypass
	nextPut := &testHandler{}
	reqPut := httptest.NewRequest(http.MethodPut, "/.env", nil)
	recPut := httptest.NewRecorder()
	if err := rw.ServeHTTP(recPut, reqPut, nextPut); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !nextPut.handled || recPut.Code != http.StatusOK {
		t.Errorf("expected PUT to bypass, got %d", recPut.Code)
	}
}

func TestRouteWarden_Methods_WhitespaceOnly_FallsBackToGET(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	rw := &caddywarden.RouteWarden{
		Enabled:               true,
		EnableDefaultPatterns: true,
		Methods:               []string{"", "   ", "  "},
	}
	if err := rw.Provision(ctx); err != nil {
		t.Fatalf("unexpected provision error: %v", err)
	}

	// Should fall back to GET as all entries are whitespace-only
	nextGet := &testHandler{}
	reqGet := httptest.NewRequest(http.MethodGet, "/.env", nil)
	recGet := httptest.NewRecorder()
	if err := rw.ServeHTTP(recGet, reqGet, nextGet); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if nextGet.handled || recGet.Code != http.StatusForbidden {
		t.Errorf("expected whitespace-only methods to default to GET and block /.env, got %d", recGet.Code)
	}

	nextPost := &testHandler{}
	reqPost := httptest.NewRequest(http.MethodPost, "/.env", nil)
	recPost := httptest.NewRecorder()
	if err := rw.ServeHTTP(recPost, reqPost, nextPost); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !nextPost.handled || recPost.Code != http.StatusOK {
		t.Errorf("expected POST to bypass when defaulted to GET-only, got %d", recPost.Code)
	}
}

func TestRouteWarden_EmptyPatternStrings(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	rw := &caddywarden.RouteWarden{
		Enabled:               true,
		EnableDefaultPatterns: false,
		PathPatterns:          []string{"", "   ", `(?i)^/secret$`, ""},
		AllowPatterns:         []string{"", "  ", `(?i)^/secret/allowed$`, ""},
	}
	if err := rw.Provision(ctx); err != nil {
		t.Fatalf("unexpected provision error: %v", err)
	}

	// /secret should be blocked
	next1 := &testHandler{}
	req1 := httptest.NewRequest(http.MethodGet, "/secret", nil)
	rec1 := httptest.NewRecorder()
	if err := rw.ServeHTTP(rec1, req1, next1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if next1.handled || rec1.Code != http.StatusForbidden {
		t.Errorf("expected /secret to be blocked, got %d", rec1.Code)
	}

	// /secret/allowed should pass
	nextAllowed := &testHandler{}
	reqAllowed := httptest.NewRequest(http.MethodGet, "/secret/allowed", nil)
	recAllowed := httptest.NewRecorder()
	if err := rw.ServeHTTP(recAllowed, reqAllowed, nextAllowed); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !nextAllowed.handled || recAllowed.Code != http.StatusOK {
		t.Errorf("expected /secret/allowed to pass, got %d", recAllowed.Code)
	}

	// /normal should pass
	next2 := &testHandler{}
	req2 := httptest.NewRequest(http.MethodGet, "/normal", nil)
	rec2 := httptest.NewRecorder()
	if err := rw.ServeHTTP(rec2, req2, next2); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !next2.handled || rec2.Code != http.StatusOK {
		t.Errorf("expected /normal to pass, got %d", rec2.Code)
	}
}

func TestRouteWarden_DebugLogs(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	rw := &caddywarden.RouteWarden{
		Enabled:                    true,
		EnableDefaultPatterns:      true,
		EnableDefaultAllowPatterns: true,
		CheckQuery:                 true,
		Debug:                      true,
		AllowedIPs:                 []string{"192.168.1.100"},
		AllowPatterns:              []string{`(?i)^/safe/endpoint$`},
		Methods:                    []string{"GET"},
	}

	if err := rw.Provision(ctx); err != nil {
		t.Fatalf("unexpected provision error: %v", err)
	}

	// 1. Method not inspected
	reqPost := httptest.NewRequest(http.MethodPost, "/.env", nil)
	recPost := httptest.NewRecorder()
	if err := rw.ServeHTTP(recPost, reqPost, &testHandler{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 2. IP whitelisted
	reqIP := httptest.NewRequest(http.MethodGet, "/.env", nil)
	reqIP.RemoteAddr = "192.168.1.100:4321"
	recIP := httptest.NewRecorder()
	if err := rw.ServeHTTP(recIP, reqIP, &testHandler{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 3. Path allowed by pattern
	reqAllow := httptest.NewRequest(http.MethodGet, "/safe/endpoint", nil)
	recAllow := httptest.NewRecorder()
	if err := rw.ServeHTTP(recAllow, reqAllow, &testHandler{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 4. Query string inspected
	reqQuery := httptest.NewRequest(http.MethodGet, "/search?file=.env", nil)
	recQuery := httptest.NewRecorder()
	if err := rw.ServeHTTP(recQuery, reqQuery, &testHandler{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 5. Normal request passed inspection
	reqPass := httptest.NewRequest(http.MethodGet, "/about", nil)
	recPass := httptest.NewRecorder()
	if err := rw.ServeHTTP(recPass, reqPass, &testHandler{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRouteWarden_SecurityLog(t *testing.T) {
	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
	rw := &caddywarden.RouteWarden{
		Enabled:               true,
		EnableDefaultPatterns: true,
		SecurityLog:           true,
		Response: &caddywarden.ResponseConfig{
			Mode:       "json",
			StatusCode: http.StatusForbidden,
		},
	}

	if err := rw.Provision(ctx); err != nil {
		t.Fatalf("unexpected provision error: %v", err)
	}

	// 1. Path block with SecurityLog enabled
	reqPath := httptest.NewRequest(http.MethodGet, "/.env", nil)
	reqPath.Header.Set("User-Agent", "CrowdSecTestAgent/1.0")
	recPath := httptest.NewRecorder()

	if err := rw.ServeHTTP(recPath, reqPath, &testHandler{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if recPath.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", recPath.Code)
	}

	// 2. Query block with SecurityLog enabled
	rwQuery := &caddywarden.RouteWarden{
		Enabled:               true,
		EnableDefaultPatterns: true,
		CheckQuery:            true,
		SecurityLog:           true,
		Response: &caddywarden.ResponseConfig{
			Mode:       "text",
			StatusCode: http.StatusForbidden,
		},
	}
	if err := rwQuery.Provision(ctx); err != nil {
		t.Fatalf("unexpected provision error: %v", err)
	}

	reqQuery := httptest.NewRequest(http.MethodGet, "/download?file=.env", nil)
	reqQuery.Header.Set("User-Agent", "CrowdSecTestAgent/1.0")
	recQuery := httptest.NewRecorder()

	if err := rwQuery.ServeHTTP(recQuery, reqQuery, &testHandler{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if recQuery.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", recQuery.Code)
	}

	// 3. SilentDrop mode with SecurityLog enabled
	rwDrop := &caddywarden.RouteWarden{
		Enabled:               true,
		EnableDefaultPatterns: true,
		SecurityLog:           true,
		Response: &caddywarden.ResponseConfig{
			Mode: "silentDrop",
		},
	}
	if err := rwDrop.Provision(ctx); err != nil {
		t.Fatalf("unexpected provision error: %v", err)
	}

	reqDrop := httptest.NewRequest(http.MethodGet, "/.env", nil)
	recDrop := httptest.NewRecorder()
	if err := rwDrop.ServeHTTP(recDrop, reqDrop, &testHandler{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 4. SecurityLog disabled - should not panic or fail
	rwDisabled := &caddywarden.RouteWarden{
		Enabled:               true,
		EnableDefaultPatterns: true,
		SecurityLog:           false,
	}
	if err := rwDisabled.Provision(ctx); err != nil {
		t.Fatalf("unexpected provision error: %v", err)
	}
	recDisabled := httptest.NewRecorder()
	if err := rwDisabled.ServeHTTP(recDisabled, reqPath, &testHandler{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRouteWarden_LiveSamplesParitySuite(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	t.Run("Section 1: Core Inspection & Built-in Patterns (:8080)", func(t *testing.T) {
		rw := &caddywarden.RouteWarden{
			Enabled:                    true,
			EnableDefaultPatterns:      true,
			EnableDefaultAllowPatterns: true,
			Methods:                    []string{"GET", "POST"},
			Response: &caddywarden.ResponseConfig{
				Mode:       "json",
				StatusCode: 403,
				Headers: map[string]string{
					"X-RouteWarden-Protection": "Active",
				},
				Body: `{"error":"Access Denied","security":"routewarden"}`,
			},
		}
		if err := rw.Provision(ctx); err != nil {
			t.Fatalf("provision error: %v", err)
		}

		// Benign request reaches upstream
		next := &testHandler{}
		req := httptest.NewRequest(http.MethodGet, "/index.html", nil)
		rec := httptest.NewRecorder()
		if err := rw.ServeHTTP(rec, req, next); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !next.handled || rec.Code != http.StatusOK {
			t.Errorf("expected 200 OK from upstream for /index.html, got %d", rec.Code)
		}

		// Built-in sensitive files
		builtins := []string{
			"/.env",
			"/.git/config",
			"/backup/production.sql",
			"/actuator/env",
		}
		for _, target := range builtins {
			nextTarget := &testHandler{}
			reqTarget := httptest.NewRequest(http.MethodGet, target, nil)
			recTarget := httptest.NewRecorder()
			if err := rw.ServeHTTP(recTarget, reqTarget, nextTarget); err != nil {
				t.Fatalf("unexpected error for %s: %v", target, err)
			}
			if nextTarget.handled || recTarget.Code != http.StatusForbidden {
				t.Errorf("expected 403 for %s, got %d", target, recTarget.Code)
			}
			if recTarget.Header().Get("X-RouteWarden-Protection") != "Active" {
				t.Errorf("expected X-RouteWarden-Protection header for %s, got %s", target, recTarget.Header().Get("X-RouteWarden-Protection"))
			}
			if !strings.Contains(recTarget.Body.String(), "Access Denied") {
				t.Errorf("expected 'Access Denied' in body for %s, got %s", target, recTarget.Body.String())
			}
		}
	})

	t.Run("Section 2: Anti-Evasion Normalization & Query Inspection (:8080)", func(t *testing.T) {
		rw := &caddywarden.RouteWarden{
			Enabled:                    true,
			EnableDefaultPatterns:      true,
			EnableDefaultAllowPatterns: true,
			CheckQuery:                 true,
			Methods:                    []string{"GET"},
		}
		if err := rw.Provision(ctx); err != nil {
			t.Fatalf("provision error: %v", err)
		}

		// Double percent-encoded traversal
		next := &testHandler{}
		req := httptest.NewRequest(http.MethodGet, "/%252e%252e/.env", nil)
		rec := httptest.NewRecorder()
		if err := rw.ServeHTTP(rec, req, next); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if next.handled || rec.Code != http.StatusForbidden {
			t.Errorf("expected 403 for double percent-encoded traversal, got %d", rec.Code)
		}

		// Semicolon matrix parameter evasion
		nextMatrix := &testHandler{}
		reqMatrix := httptest.NewRequest(http.MethodGet, "/;.env", nil)
		recMatrix := httptest.NewRecorder()
		if err := rw.ServeHTTP(recMatrix, reqMatrix, nextMatrix); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if nextMatrix.handled || recMatrix.Code != http.StatusForbidden {
			t.Errorf("expected 403 for /;.env, got %d", recMatrix.Code)
		}

		// Query string inspection
		nextQuery := &testHandler{}
		reqQuery := httptest.NewRequest(http.MethodGet, "/search?file=.env", nil)
		recQuery := httptest.NewRecorder()
		if err := rw.ServeHTTP(recQuery, reqQuery, nextQuery); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if nextQuery.handled || recQuery.Code != http.StatusForbidden {
			t.Errorf("expected 403 for ?file=.env, got %d", recQuery.Code)
		}

		// Encoded query parameter inspection
		nextEncQuery := &testHandler{}
		reqEncQuery := httptest.NewRequest(http.MethodGet, "/download?q=%2e%65%6e%76", nil)
		recEncQuery := httptest.NewRecorder()
		if err := rw.ServeHTTP(recEncQuery, reqEncQuery, nextEncQuery); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if nextEncQuery.handled || recEncQuery.Code != http.StatusForbidden {
			t.Errorf("expected 403 for ?q=%%2e%%65%%6e%%76, got %d", recEncQuery.Code)
		}
	})

	t.Run("Section 3: Pattern Allowlist & IP Whitelist Flags (:8080)", func(t *testing.T) {
		rw := &caddywarden.RouteWarden{
			Enabled:                    true,
			EnableDefaultPatterns:      true,
			EnableDefaultAllowPatterns: true,
			PathPatterns:               []string{`(?i)^/admin/secret.*$`},
			AllowPatterns:              []string{`(?i)^/api/healthz$`},
			AllowedIPs:                 []string{"192.168.100.50", "10.99.0.0/16"},
			Methods:                    []string{"GET"},
		}
		if err := rw.Provision(ctx); err != nil {
			t.Fatalf("provision error: %v", err)
		}

		// Default allowlist exemption: /robots.txt
		nextRobots := &testHandler{}
		reqRobots := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
		recRobots := httptest.NewRecorder()
		if err := rw.ServeHTTP(recRobots, reqRobots, nextRobots); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !nextRobots.handled || recRobots.Code != http.StatusOK {
			t.Errorf("expected 200 for /robots.txt, got %d", recRobots.Code)
		}

		// Custom allow pattern: /api/healthz
		nextHealth := &testHandler{}
		reqHealth := httptest.NewRequest(http.MethodGet, "/api/healthz", nil)
		recHealth := httptest.NewRecorder()
		if err := rw.ServeHTTP(recHealth, reqHealth, nextHealth); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !nextHealth.handled || recHealth.Code != http.StatusOK {
			t.Errorf("expected 200 for /api/healthz, got %d", recHealth.Code)
		}

		// Custom path_patterns: /admin/secret-keys
		nextAdmin := &testHandler{}
		reqAdmin := httptest.NewRequest(http.MethodGet, "/admin/secret-keys", nil)
		recAdmin := httptest.NewRecorder()
		if err := rw.ServeHTTP(recAdmin, reqAdmin, nextAdmin); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if nextAdmin.handled || recAdmin.Code != http.StatusForbidden {
			t.Errorf("expected 403 for /admin/secret-keys, got %d", recAdmin.Code)
		}

		// Whitelisted IP bypass (192.168.100.50)
		nextIPAllowed := &testHandler{}
		reqIPAllowed := httptest.NewRequest(http.MethodGet, "/.env", nil)
		reqIPAllowed.Header.Set("X-Forwarded-For", "192.168.100.50")
		recIPAllowed := httptest.NewRecorder()
		if err := rw.ServeHTTP(recIPAllowed, reqIPAllowed, nextIPAllowed); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !nextIPAllowed.handled || recIPAllowed.Code != http.StatusOK {
			t.Errorf("expected 200 for whitelisted IP bypassing /.env, got %d", recIPAllowed.Code)
		}

		// Non-whitelisted IP blocked (8.8.8.8)
		nextIPBlocked := &testHandler{}
		reqIPBlocked := httptest.NewRequest(http.MethodGet, "/.env", nil)
		reqIPBlocked.Header.Set("X-Forwarded-For", "8.8.8.8")
		recIPBlocked := httptest.NewRecorder()
		if err := rw.ServeHTTP(recIPBlocked, reqIPBlocked, nextIPBlocked); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if nextIPBlocked.handled || recIPBlocked.Code != http.StatusForbidden {
			t.Errorf("expected 403 for non-whitelisted IP, got %d", recIPBlocked.Code)
		}
	})

	t.Run("Section 4: All Response Modes (:8081 - :8091)", func(t *testing.T) {
		// Port 8081: HTML mode
		rwHTML := &caddywarden.RouteWarden{
			Enabled:               true,
			EnableDefaultPatterns: true,
			Response: &caddywarden.ResponseConfig{
				Mode:       "html",
				StatusCode: 403,
				Headers:    map[string]string{"X-RouteWarden-Mode": "html"},
				Body:       "<html><body><h1>Access Denied by RouteWarden</h1></body></html>",
			},
		}
		if err := rwHTML.Provision(ctx); err != nil {
			t.Fatalf("provision error: %v", err)
		}
		recHTML := httptest.NewRecorder()
		_ = rwHTML.ServeHTTP(recHTML, httptest.NewRequest(http.MethodGet, "/.env", nil), &testHandler{})
		if recHTML.Code != 403 || !strings.Contains(recHTML.Body.String(), "<h1>Access Denied by RouteWarden</h1>") || !strings.Contains(recHTML.Header().Get("Content-Type"), "text/html") {
			t.Errorf("unexpected HTML response: %d, %s, %s", recHTML.Code, recHTML.Header().Get("Content-Type"), recHTML.Body.String())
		}

		// Port 8082: Text mode
		rwText := &caddywarden.RouteWarden{
			Enabled:               true,
			EnableDefaultPatterns: true,
			Response: &caddywarden.ResponseConfig{
				Mode:       "text",
				StatusCode: 403,
				Headers:    map[string]string{"X-RouteWarden-Mode": "text"},
				Body:       "Access Forbidden: RouteWarden Text Mode",
			},
		}
		if err := rwText.Provision(ctx); err != nil {
			t.Fatalf("provision error: %v", err)
		}
		recText := httptest.NewRecorder()
		_ = rwText.ServeHTTP(recText, httptest.NewRequest(http.MethodGet, "/.env", nil), &testHandler{})
		if recText.Code != 403 || !strings.Contains(recText.Body.String(), "Access Forbidden: RouteWarden Text Mode") || !strings.Contains(recText.Header().Get("Content-Type"), "text/plain") {
			t.Errorf("unexpected Text response: %d, %s, %s", recText.Code, recText.Header().Get("Content-Type"), recText.Body.String())
		}

		// Port 8083: XML mode
		rwXML := &caddywarden.RouteWarden{
			Enabled:               true,
			EnableDefaultPatterns: true,
			Response: &caddywarden.ResponseConfig{
				Mode:       "xml",
				StatusCode: 403,
				Headers:    map[string]string{"X-RouteWarden-Mode": "xml"},
			},
		}
		if err := rwXML.Provision(ctx); err != nil {
			t.Fatalf("provision error: %v", err)
		}
		recXML := httptest.NewRecorder()
		_ = rwXML.ServeHTTP(recXML, httptest.NewRequest(http.MethodGet, "/.env", nil), &testHandler{})
		if recXML.Code != 403 || !strings.Contains(recXML.Body.String(), "<Error>") || !strings.Contains(recXML.Header().Get("Content-Type"), "application/xml") {
			t.Errorf("unexpected XML response: %d, %s, %s", recXML.Code, recXML.Header().Get("Content-Type"), recXML.Body.String())
		}

		// Port 8084: Captcha mode (turnstile)
		rwCaptcha := &caddywarden.RouteWarden{
			Enabled:               true,
			EnableDefaultPatterns: true,
			Response: &caddywarden.ResponseConfig{
				Mode:       "captcha",
				StatusCode: 403,
				Captcha: &caddywarden.CaptchaConfig{
					Provider: "turnstile",
					SiteKey:  "0x4AAAAAAtestkey",
					Title:    "Security Verification Challenge",
				},
			},
		}
		if err := rwCaptcha.Provision(ctx); err != nil {
			t.Fatalf("provision error: %v", err)
		}
		recCaptcha := httptest.NewRecorder()
		_ = rwCaptcha.ServeHTTP(recCaptcha, httptest.NewRequest(http.MethodGet, "/.env", nil), &testHandler{})
		if recCaptcha.Code != 403 || !strings.Contains(recCaptcha.Body.String(), "cf-turnstile") || !strings.Contains(recCaptcha.Body.String(), "0x4AAAAAAtestkey") {
			t.Errorf("unexpected Captcha response: %d, %s", recCaptcha.Code, recCaptcha.Body.String())
		}

		// Port 8085: Redirect mode
		rwRedirect := &caddywarden.RouteWarden{
			Enabled:               true,
			EnableDefaultPatterns: true,
			Response: &caddywarden.ResponseConfig{
				Mode:        "redirect",
				StatusCode:  302,
				RedirectURL: "https://honeypot.local/sinkhole",
			},
		}
		if err := rwRedirect.Provision(ctx); err != nil {
			t.Fatalf("provision error: %v", err)
		}
		recRedirect := httptest.NewRecorder()
		_ = rwRedirect.ServeHTTP(recRedirect, httptest.NewRequest(http.MethodGet, "/.env", nil), &testHandler{})
		if recRedirect.Code != 302 || recRedirect.Header().Get("Location") != "https://honeypot.local/sinkhole" {
			t.Errorf("unexpected Redirect response: %d, Location: %s", recRedirect.Code, recRedirect.Header().Get("Location"))
		}

		// Port 8086: RateLimitChallenge mode
		rwRate := &caddywarden.RouteWarden{
			Enabled:               true,
			EnableDefaultPatterns: true,
			Response: &caddywarden.ResponseConfig{
				Mode:              "rateLimitChallenge",
				StatusCode:        429,
				RetryAfterSeconds: 180,
			},
		}
		if err := rwRate.Provision(ctx); err != nil {
			t.Fatalf("provision error: %v", err)
		}
		recRate := httptest.NewRecorder()
		_ = rwRate.ServeHTTP(recRate, httptest.NewRequest(http.MethodGet, "/.env", nil), &testHandler{})
		if recRate.Code != 429 || recRate.Header().Get("Retry-After") != "180" || !strings.Contains(recRate.Body.String(), "Too Many Requests") {
			t.Errorf("unexpected RateLimit response: %d, Retry-After: %s, Body: %s", recRate.Code, recRate.Header().Get("Retry-After"), recRate.Body.String())
		}

		// Port 8087: FakeSuccess / Decoy mode
		rwFake := &caddywarden.RouteWarden{
			Enabled:               true,
			EnableDefaultPatterns: true,
			Response: &caddywarden.ResponseConfig{
				Mode: "fakeSuccess",
			},
		}
		if err := rwFake.Provision(ctx); err != nil {
			t.Fatalf("provision error: %v", err)
		}
		recFake := httptest.NewRecorder()
		_ = rwFake.ServeHTTP(recFake, httptest.NewRequest(http.MethodGet, "/.env", nil), &testHandler{})
		if recFake.Code != 200 || !strings.Contains(recFake.Body.String(), "APP_NAME=Laravel") || !strings.Contains(recFake.Body.String(), "DB_PASSWORD=") {
			t.Errorf("unexpected FakeSuccess response: %d, Body: %s", recFake.Code, recFake.Body.String())
		}

		// Port 8088: GzipBomb mode
		rwBomb := &caddywarden.RouteWarden{
			Enabled:               true,
			EnableDefaultPatterns: true,
			Response: &caddywarden.ResponseConfig{
				Mode:        "gzipBomb",
				StatusCode:  200,
				GzipBombMB:  1,
			},
		}
		if err := rwBomb.Provision(ctx); err != nil {
			t.Fatalf("provision error: %v", err)
		}
		recBomb := httptest.NewRecorder()
		_ = rwBomb.ServeHTTP(recBomb, httptest.NewRequest(http.MethodGet, "/.env", nil), &testHandler{})
		if recBomb.Header().Get("Content-Encoding") != "gzip" {
			t.Errorf("expected gzip Content-Encoding, got %s", recBomb.Header().Get("Content-Encoding"))
		}

		// Port 8089: SilentDrop mode
		rwDrop := &caddywarden.RouteWarden{
			Enabled:               true,
			EnableDefaultPatterns: true,
			Response: &caddywarden.ResponseConfig{
				Mode: "silentDrop",
			},
		}
		if err := rwDrop.Provision(ctx); err != nil {
			t.Fatalf("provision error: %v", err)
		}
		recDrop := httptest.NewRecorder()
		_ = rwDrop.ServeHTTP(recDrop, httptest.NewRequest(http.MethodGet, "/.env", nil), &testHandler{})
		if recDrop.Code != 403 {
			t.Errorf("expected 403 status fallback for SilentDrop in test recorder, got %d", recDrop.Code)
		}

		// Port 8090: InfiniteStream mode
		rwStream := &caddywarden.RouteWarden{
			Enabled:               true,
			EnableDefaultPatterns: true,
			Response: &caddywarden.ResponseConfig{
				Mode:         "infiniteStream",
				StatusCode:   200,
				StreamSizeMB: 1,
			},
		}
		if err := rwStream.Provision(ctx); err != nil {
			t.Fatalf("provision error: %v", err)
		}
		recStream := httptest.NewRecorder()
		_ = rwStream.ServeHTTP(recStream, httptest.NewRequest(http.MethodGet, "/.env", nil), &testHandler{})
		if recStream.Code != 200 || recStream.Body.Len() == 0 {
			t.Errorf("expected non-empty stream with 200, got code %d and len %d", recStream.Code, recStream.Body.Len())
		}
	})

	t.Run("Section 5: Operational Flags: disable & methods (:8092, :8093)", func(t *testing.T) {
		// Port 8092: disable flag
		rwDisabled := &caddywarden.RouteWarden{
			Enabled:               false,
			EnableDefaultPatterns: true,
		}
		if err := rwDisabled.Provision(ctx); err != nil {
			t.Fatalf("provision error: %v", err)
		}
		nextDisabled := &testHandler{}
		reqDisabled := httptest.NewRequest(http.MethodGet, "/.env", nil)
		recDisabled := httptest.NewRecorder()
		if err := rwDisabled.ServeHTTP(recDisabled, reqDisabled, nextDisabled); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !nextDisabled.handled || recDisabled.Code != http.StatusOK {
			t.Errorf("expected disabled RouteWarden to bypass to upstream with 200, got %d", recDisabled.Code)
		}

		// Port 8093: methods filter (inspects only POST & DELETE)
		rwMethods := &caddywarden.RouteWarden{
			Enabled:               true,
			EnableDefaultPatterns: true,
			Methods:               []string{"POST", "DELETE"},
			Response: &caddywarden.ResponseConfig{
				Mode:       "json",
				StatusCode: 403,
			},
		}
		if err := rwMethods.Provision(ctx); err != nil {
			t.Fatalf("provision error: %v", err)
		}

		// GET should bypass
		nextGet := &testHandler{}
		reqGet := httptest.NewRequest(http.MethodGet, "/.env", nil)
		recGet := httptest.NewRecorder()
		if err := rwMethods.ServeHTTP(recGet, reqGet, nextGet); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !nextGet.handled || recGet.Code != http.StatusOK {
			t.Errorf("expected GET to bypass methods filter with 200, got %d", recGet.Code)
		}

		// POST should be inspected and blocked
		nextPost := &testHandler{}
		reqPost := httptest.NewRequest(http.MethodPost, "/.env", nil)
		recPost := httptest.NewRecorder()
		if err := rwMethods.ServeHTTP(recPost, reqPost, nextPost); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if nextPost.handled || recPost.Code != http.StatusForbidden {
			t.Errorf("expected POST to be blocked with 403, got %d", recPost.Code)
		}

		// DELETE should be inspected and blocked
		nextDelete := &testHandler{}
		reqDelete := httptest.NewRequest(http.MethodDelete, "/.env", nil)
		recDelete := httptest.NewRecorder()
		if err := rwMethods.ServeHTTP(recDelete, reqDelete, nextDelete); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if nextDelete.handled || recDelete.Code != http.StatusForbidden {
			t.Errorf("expected DELETE to be blocked with 403, got %d", recDelete.Code)
		}
	})

	t.Run("Expanded default block patterns (keys, container, wp-config, ds_store)", func(t *testing.T) {
		rw := &caddywarden.RouteWarden{
			Enabled:               true,
			EnableDefaultPatterns: true,
		}
		if err := rw.Provision(ctx); err != nil {
			t.Fatalf("unexpected provision error: %v", err)
		}

		paths := []string{
			"/server.key",
			"/cert.pem",
			"/Dockerfile",
			"/docker-compose.yml",
			"/.DS_Store",
			"/wp-config.php",
		}

		for _, p := range paths {
			next := &testHandler{}
			req := httptest.NewRequest(http.MethodGet, p, nil)
			rec := httptest.NewRecorder()
			if err := rw.ServeHTTP(rec, req, next); err != nil {
				t.Fatalf("unexpected error on %s: %v", p, err)
			}
			if next.handled || rec.Code != http.StatusForbidden {
				t.Errorf("expected %s to be blocked by default patterns, got code %d", p, rec.Code)
			}
		}
	})

	t.Run("CheckHeaders inspection", func(t *testing.T) {
		rw := &caddywarden.RouteWarden{
			Enabled:               true,
			EnableDefaultPatterns: true,
			CheckHeaders:          []string{"X-Forwarded-Uri", "X-Rewrite-URL"},
		}
		if err := rw.Provision(ctx); err != nil {
			t.Fatalf("unexpected provision error: %v", err)
		}

		// Benign header passes
		nextClean := &testHandler{}
		reqClean := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
		reqClean.Header.Set("X-Forwarded-Uri", "/dashboard")
		recClean := httptest.NewRecorder()
		if err := rw.ServeHTTP(recClean, reqClean, nextClean); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !nextClean.handled || recClean.Code != http.StatusOK {
			t.Errorf("expected 200 for benign header, got %d", recClean.Code)
		}

		// Smuggled .env in X-Forwarded-Uri gets blocked
		nextSmuggled := &testHandler{}
		reqSmuggled := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
		reqSmuggled.Header.Set("X-Forwarded-Uri", "/.env")
		recSmuggled := httptest.NewRecorder()
		if err := rw.ServeHTTP(recSmuggled, reqSmuggled, nextSmuggled); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if nextSmuggled.handled || recSmuggled.Code != http.StatusForbidden {
			t.Errorf("expected 403 for smuggled .env in header, got %d", recSmuggled.Code)
		}
	})
}

