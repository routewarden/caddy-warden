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


