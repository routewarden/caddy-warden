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

func TestCaddyfile_ComprehensiveDirectives(t *testing.T) {
	caddyfileInput := `
	routewarden {
		disable
		disable_default_patterns
		disable_default_allow_patterns
		check_query
		path_patterns (?i)^/block1$ (?i)^/block2$
		block_patterns (?i)^/block3$
		allow_patterns (?i)^/allow1$ (?i)^/allow2$
		allowed_ips 192.168.1.1 10.0.0.0/24
		methods GET POST
		response {
			mode captcha
			status 429
			content_type application/custom+json
			body "Custom Body Content"
			redirect_url https://honeypot.internal/sink
			proxy_url http://127.0.0.1:9999
			gzip_bomb_mb 15
			retry_after 120
			tarpit_delay_ms 500
			tarpit_max_duration 45
			stream_size_mb 50
			header X-Warden-Shield Active
			header X-Block-Reason SecurityPolicy
			captcha turnstile my-site-key "Security Verification Challenge"
		}
	}
	`

	d := caddyfile.NewTestDispenser(caddyfileInput)
	rw := &caddywarden.RouteWarden{}
	err := rw.UnmarshalCaddyfile(d)
	if err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	if rw.Enabled {
		t.Errorf("expected rw.Enabled to be false")
	}
	if rw.EnableDefaultPatterns {
		t.Errorf("expected rw.EnableDefaultPatterns to be false")
	}
	if rw.EnableDefaultAllowPatterns {
		t.Errorf("expected rw.EnableDefaultAllowPatterns to be false")
	}
	if !rw.CheckQuery {
		t.Errorf("expected rw.CheckQuery to be true")
	}
	if len(rw.PathPatterns) != 3 {
		t.Errorf("expected 3 path_patterns, got %d", len(rw.PathPatterns))
	}
	if len(rw.AllowPatterns) != 2 {
		t.Errorf("expected 2 allow_patterns, got %d", len(rw.AllowPatterns))
	}
	if len(rw.AllowedIPs) != 2 {
		t.Errorf("expected 2 allowed_ips, got %d", len(rw.AllowedIPs))
	}
	if len(rw.Methods) != 2 || rw.Methods[0] != "GET" || rw.Methods[1] != "POST" {
		t.Errorf("expected methods [GET POST], got %v", rw.Methods)
	}

	resp := rw.Response
	if resp == nil {
		t.Fatalf("expected response config to be non-nil")
	}
	if resp.Mode != "captcha" {
		t.Errorf("expected mode captcha, got %s", resp.Mode)
	}
	if resp.StatusCode != 429 {
		t.Errorf("expected statusCode 429, got %d", resp.StatusCode)
	}
	if resp.ContentType != "application/custom+json" {
		t.Errorf("expected custom contentType, got %s", resp.ContentType)
	}
	if resp.Body != "Custom Body Content" {
		t.Errorf("expected custom body, got %s", resp.Body)
	}
	if resp.RedirectURL != "https://honeypot.internal/sink" {
		t.Errorf("expected redirectUrl, got %s", resp.RedirectURL)
	}
	if resp.ProxyURL != "http://127.0.0.1:9999" {
		t.Errorf("expected proxyUrl, got %s", resp.ProxyURL)
	}
	if resp.GzipBombMB != 15 {
		t.Errorf("expected gzipBombMB 15, got %d", resp.GzipBombMB)
	}
	if resp.RetryAfterSeconds != 120 {
		t.Errorf("expected retryAfterSeconds 120, got %d", resp.RetryAfterSeconds)
	}
	if resp.TarpitDelayMs != 500 {
		t.Errorf("expected tarpitDelayMs 500, got %d", resp.TarpitDelayMs)
	}
	if resp.TarpitMaxDurationSeconds != 45 {
		t.Errorf("expected tarpitMaxDurationSeconds 45, got %d", resp.TarpitMaxDurationSeconds)
	}
	if resp.StreamSizeMB != 50 {
		t.Errorf("expected streamSizeMB 50, got %d", resp.StreamSizeMB)
	}
	if resp.Headers["X-Warden-Shield"] != "Active" || resp.Headers["X-Block-Reason"] != "SecurityPolicy" {
		t.Errorf("expected headers to match, got %+v", resp.Headers)
	}
	if resp.Captcha == nil {
		t.Fatalf("expected captcha config to be non-nil")
	}
	if resp.Captcha.Provider != "turnstile" || resp.Captcha.SiteKey != "my-site-key" || resp.Captcha.Title != "Security Verification Challenge" {
		t.Errorf("unexpected captcha config: %+v", resp.Captcha)
	}

	// Test mode silentDrop parsing and execution
	silentDropInput := `
	routewarden {
		response {
			mode silentDrop
		}
	}
	`
	sdDispenser := caddyfile.NewTestDispenser(silentDropInput)
	sdRw := &caddywarden.RouteWarden{}
	if err := sdRw.UnmarshalCaddyfile(sdDispenser); err != nil {
		t.Fatalf("unexpected unmarshal error for silentDrop: %v", err)
	}
	sdCtx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
	if err := sdRw.Provision(sdCtx); err != nil {
		t.Fatalf("failed to provision silentDrop module: %v", err)
	}
	recSD := httptest.NewRecorder()
	reqSD := httptest.NewRequest(http.MethodGet, "/.env", nil)
	if err := sdRw.ServeHTTP(recSD, reqSD, &testHandler{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if recSD.Body.Len() > 0 {
		t.Errorf("expected empty body for silentDrop mode, got %s", recSD.Body.String())
	}
}

func TestCaddyfile_ParsingErrors(t *testing.T) {
	invalidConfigs := []struct {
		name string
		cfg  string
	}{
		{"empty path_patterns", "routewarden {\n path_patterns\n}"},
		{"empty allow_patterns", "routewarden {\n allow_patterns\n}"},
		{"empty allowed_ips", "routewarden {\n allowed_ips\n}"},
		{"empty methods", "routewarden {\n methods\n}"},
		{"unknown routewarden directive", "routewarden {\n unknown_directive\n}"},
		{"empty response mode", "routewarden {\n response {\n mode\n }\n}"},
		{"empty response status", "routewarden {\n response {\n status\n }\n}"},
		{"invalid response status non-int", "routewarden {\n response {\n status abc\n }\n}"},
		{"empty content_type", "routewarden {\n response {\n content_type\n }\n}"},
		{"empty body", "routewarden {\n response {\n body\n }\n}"},
		{"empty redirect_url", "routewarden {\n response {\n redirect_url\n }\n}"},
		{"empty proxy_url", "routewarden {\n response {\n proxy_url\n }\n}"},
		{"empty gzip_bomb_mb", "routewarden {\n response {\n gzip_bomb_mb\n }\n}"},
		{"invalid gzip_bomb_mb non-int", "routewarden {\n response {\n gzip_bomb_mb abc\n }\n}"},
		{"empty retry_after", "routewarden {\n response {\n retry_after\n }\n}"},
		{"invalid retry_after non-int", "routewarden {\n response {\n retry_after abc\n }\n}"},
		{"empty tarpit_delay_ms", "routewarden {\n response {\n tarpit_delay_ms\n }\n}"},
		{"invalid tarpit_delay_ms non-int", "routewarden {\n response {\n tarpit_delay_ms abc\n }\n}"},
		{"empty tarpit_max_duration", "routewarden {\n response {\n tarpit_max_duration\n }\n}"},
		{"invalid tarpit_max_duration non-int", "routewarden {\n response {\n tarpit_max_duration abc\n }\n}"},
		{"empty stream_size_mb", "routewarden {\n response {\n stream_size_mb\n }\n}"},
		{"invalid stream_size_mb non-int", "routewarden {\n response {\n stream_size_mb abc\n }\n}"},
		{"missing header value", "routewarden {\n response {\n header X-Key\n }\n}"},
		{"missing captcha key", "routewarden {\n response {\n captcha turnstile\n }\n}"},
		{"unknown response subdirective", "routewarden {\n response {\n bogus_option\n }\n}"},
	}

	for _, tc := range invalidConfigs {
		t.Run(tc.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tc.cfg)
			rw := &caddywarden.RouteWarden{}
			err := rw.UnmarshalCaddyfile(d)
			if err == nil {
				t.Errorf("expected error for config %q, got nil", tc.cfg)
			}
		})
	}
}



func TestCaddyfile_MethodsDirective(t *testing.T) {
	t.Run("Default methods when omitted", func(t *testing.T) {
		input := `
		routewarden {
			path_patterns (?i)^/secret$
		}
		`
		d := caddyfile.NewTestDispenser(input)
		rw := &caddywarden.RouteWarden{}
		if err := rw.UnmarshalCaddyfile(d); err != nil {
			t.Fatalf("unexpected unmarshal error: %v", err)
		}
		if len(rw.Methods) != 1 || rw.Methods[0] != "GET" {
			t.Errorf("expected default Methods to be [GET], got %v", rw.Methods)
		}
	})

	t.Run("Single custom method", func(t *testing.T) {
		input := `
		routewarden {
			methods POST
		}
		`
		d := caddyfile.NewTestDispenser(input)
		rw := &caddywarden.RouteWarden{}
		if err := rw.UnmarshalCaddyfile(d); err != nil {
			t.Fatalf("unexpected unmarshal error: %v", err)
		}
		if len(rw.Methods) != 1 || rw.Methods[0] != "POST" {
			t.Errorf("expected Methods to be [POST], got %v", rw.Methods)
		}
	})

	t.Run("Multiple custom methods", func(t *testing.T) {
		input := `
		routewarden {
			methods GET POST DELETE PUT
		}
		`
		d := caddyfile.NewTestDispenser(input)
		rw := &caddywarden.RouteWarden{}
		if err := rw.UnmarshalCaddyfile(d); err != nil {
			t.Fatalf("unexpected unmarshal error: %v", err)
		}
		expected := []string{"GET", "POST", "DELETE", "PUT"}
		if len(rw.Methods) != len(expected) {
			t.Fatalf("expected %d methods, got %d", len(expected), len(rw.Methods))
		}
		for i, m := range expected {
			if rw.Methods[i] != m {
				t.Errorf("expected method %d to be %s, got %s", i, m, rw.Methods[i])
			}
		}
	})

	t.Run("Modes through Caddyfile", func(t *testing.T) {
		testModes := map[string]string{
			"json":               "",
			"html":               "",
			"text":               "",
			"xml":                "",
			"redirect":           "redirect_url https://honeypot.local/trap",
			"fakeSuccess":        "",
			"rateLimitChallenge": "",
			"gzipBomb":           "",
			"proxy":              "proxy_url http://127.0.0.1:9099",
		}

		for mode, extra := range testModes {
			t.Run(mode, func(t *testing.T) {
				cfg := "routewarden {\n response {\n mode " + mode + "\n " + extra + "\n }\n}"
				d := caddyfile.NewTestDispenser(cfg)
				rw := &caddywarden.RouteWarden{}
				if err := rw.UnmarshalCaddyfile(d); err != nil {
					t.Fatalf("failed to parse mode %s: %v", mode, err)
				}
				ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
				if err := rw.Provision(ctx); err != nil {
					t.Fatalf("failed to provision mode %s: %v", mode, err)
				}
				rec := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodGet, "/.env", nil)
				if err := rw.ServeHTTP(rec, req, &testHandler{}); err != nil {
					t.Fatalf("unexpected error for mode %s: %v", mode, err)
				}
				if rec.Code == 0 {
					t.Errorf("expected non-zero status code")
				}
			})
		}
	})
}
