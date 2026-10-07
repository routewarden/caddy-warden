package caddywarden_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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
		block_patterns (?i)^/admin/secret$
		check_query
		response {
			mode json
			status_code 403
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
		enabled false
		enable_default_patterns false
		enable_default_allow_patterns false
		check_query
		debug
		security_log true
		block_patterns (?i)^/block1$ (?i)^/block2$ (?i)^/block3$
		allow_patterns (?i)^/allow1$ (?i)^/allow2$
		allowed_ips 192.168.1.1 10.0.0.0/24
		methods GET POST
		response {
			mode captcha
			status_code 429
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
	if !rw.Debug {
		t.Errorf("expected rw.Debug to be true")
	}
	if !rw.SecurityLog {
		t.Errorf("expected rw.SecurityLog to be true")
	}
	if len(rw.BlockPatterns) != 3 {
		t.Errorf("expected 3 block_patterns, got %d", len(rw.BlockPatterns))
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
		{"empty block_patterns", "routewarden {\n block_patterns\n}"},
		{"empty allow_patterns", "routewarden {\n allow_patterns\n}"},
		{"empty allowed_ips", "routewarden {\n allowed_ips\n}"},
		{"empty methods", "routewarden {\n methods\n}"},
		{"unknown routewarden directive", "routewarden {\n unknown_directive\n}"},
		{"empty response mode", "routewarden {\n response {\n mode\n }\n}"},
		{"empty response status_code", "routewarden {\n response {\n status_code\n }\n}"},
		{"empty response status (alias)", "routewarden {\n response {\n status\n }\n}"},
		{"invalid response status non-int", "routewarden {\n response {\n status abc\n }\n}"},
		{"invalid response status_code non-int", "routewarden {\n response {\n status_code abc\n }\n}"},
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



func TestCaddyfile_StatusAlias(t *testing.T) {
	// "status" must be accepted as an alias for "status_code" inside the response block.
	// This was the root cause of block_patterns appearing to have no effect:
	// every example Caddyfile used "status", which triggered an unrecognized-subdirective
	// error causing the entire routewarden block to fail provisioning.
	input := `routewarden {
		block_patterns (?i)^/secret$
		response {
			mode json
			status 404
		}
	}`
	d := caddyfile.NewTestDispenser(input)
	rw := &caddywarden.RouteWarden{}
	if err := rw.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("status alias: unexpected unmarshal error: %v", err)
	}
	if rw.Response == nil {
		t.Fatal("status alias: Response is nil")
	}
	if rw.Response.StatusCode != 404 {
		t.Errorf("status alias: expected StatusCode 404, got %d", rw.Response.StatusCode)
	}
}

func TestCaddyfile_MethodsDirective(t *testing.T) {
	t.Run("Default methods when omitted", func(t *testing.T) {
		input := `
		routewarden {
			block_patterns (?i)^/secret$
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
				if mode == "xml" && !strings.Contains(rec.Body.String(), "<Error>") {
					t.Errorf("expected xml mode without body to generate XML default, got: %s", rec.Body.String())
				}
				if mode == "fakeSuccess" && !strings.Contains(rec.Body.String(), "APP_NAME=Laravel") {
					t.Errorf("expected fakeSuccess mode without body to generate decoy .env, got: %s", rec.Body.String())
				}
				if mode == "rateLimitChallenge" && !strings.Contains(rec.Body.String(), "Too Many Requests") {
					t.Errorf("expected rateLimitChallenge mode without body to generate default rate limit body, got: %s", rec.Body.String())
				}
			})
		}
	})

	t.Run("Disabled flag survives Caddy JSON roundtrip", func(t *testing.T) {
		cfg := "routewarden {\n enabled false\n}"
		d := caddyfile.NewTestDispenser(cfg)
		rw := &caddywarden.RouteWarden{}
		if err := rw.UnmarshalCaddyfile(d); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}
		if rw.Enabled {
			t.Fatalf("expected Enabled=false after unmarshaling Caddyfile")
		}

		// Marshal to JSON (as Caddy does when adapting Caddyfile to JSON config)
		data, err := json.Marshal(rw)
		if err != nil {
			t.Fatalf("failed to marshal JSON: %v", err)
		}
		if !strings.Contains(string(data), `"enabled":false`) {
			t.Fatalf("expected JSON to contain '\"enabled\":false', got: %s", string(data))
		}

		// Unmarshal into a fresh module instance (as Caddy's New() does, where Enabled is true by default)
		mod := caddywarden.RouteWarden{}.CaddyModule().New().(*caddywarden.RouteWarden)
		if !mod.Enabled {
			t.Fatalf("sanity check failed: module default should have Enabled=true")
		}
		if err := json.Unmarshal(data, mod); err != nil {
			t.Fatalf("failed to unmarshal JSON: %v", err)
		}
		if mod.Enabled {
			t.Fatalf("expected unmarshaled module to have Enabled=false, got true")
		}
	})

	t.Run("check_headers parsing", func(t *testing.T) {
		cfg := `routewarden {
			check_headers X-Forwarded-Uri X-Rewrite-URL
		}`
		d := caddyfile.NewTestDispenser(cfg)
		rw := &caddywarden.RouteWarden{}
		if err := rw.UnmarshalCaddyfile(d); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}
		if len(rw.CheckHeaders) != 2 || rw.CheckHeaders[0] != "X-Forwarded-Uri" || rw.CheckHeaders[1] != "X-Rewrite-URL" {
			t.Fatalf("unexpected CheckHeaders: %v", rw.CheckHeaders)
		}
	})

	t.Run("mode silent_drop and silentDrop configuration", func(t *testing.T) {
		tests := []struct {
			name        string
			caddyfile   string
			wantMode    string
		}{
			{
				name: "top-level mode silent_drop",
				caddyfile: `routewarden {
					mode silent_drop
				}`,
				wantMode: "silentDrop",
			},
			{
				name: "top-level mode silentDrop",
				caddyfile: `routewarden {
					mode silentDrop
				}`,
				wantMode: "silentDrop",
			},
			{
				name: "response block mode silent_drop",
				caddyfile: `routewarden {
					response {
						mode silent_drop
					}
				}`,
				wantMode: "silentDrop",
			},
			{
				name: "response block mode silentDrop",
				caddyfile: `routewarden {
					response {
						mode silentDrop
					}
				}`,
				wantMode: "silentDrop",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				d := caddyfile.NewTestDispenser(tc.caddyfile)
				rw := &caddywarden.RouteWarden{}
				if err := rw.UnmarshalCaddyfile(d); err != nil {
					t.Fatalf("failed to unmarshal: %v", err)
				}
				ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
				if err := rw.Provision(ctx); err != nil {
					t.Fatalf("failed to provision: %v", err)
				}
				if rw.Response.Mode != tc.wantMode {
					t.Errorf("expected Response.Mode=%q, got %q", tc.wantMode, rw.Response.Mode)
				}
			})
		}
	})

	t.Run("legacy silent_drop directive rejected", func(t *testing.T) {
		caddyfileSnippet := `routewarden {
			silent_drop
		}`
		d := caddyfile.NewTestDispenser(caddyfileSnippet)
		rw := &caddywarden.RouteWarden{}
		err := rw.UnmarshalCaddyfile(d)
		if err == nil {
			t.Fatal("expected error for unmarshaling unrecognized legacy silent_drop directive, got nil")
		}
	})

	t.Run("removed duplicate aliases error", func(t *testing.T) {
		aliases := []string{
			"path_pattern (?i)^/p$",
			"block_pattern (?i)^/p$",
			"allow_pattern (?i)^/p$",
			"allowed_ip 192.168.1.1",
			"path_patterns (?i)^/p$",
			"body_patterns (?i)secret",
			"body_pattern (?i)secret",
		}
		for _, alias := range aliases {
			snippet := fmt.Sprintf("routewarden {\n%s\n}", alias)
			d := caddyfile.NewTestDispenser(snippet)
			rw := &caddywarden.RouteWarden{}
			if err := rw.UnmarshalCaddyfile(d); err == nil {
				t.Errorf("expected error for removed duplicate alias %q, got nil", alias)
			}
		}
	})

	t.Run("check_body and check_body_patterns directives", func(t *testing.T) {
		snippet := `routewarden {
			check_body
			check_body_max_bytes 32768
			check_body_patterns "(?i)grant_type=password" "malicious_payload"
		}`
		d := caddyfile.NewTestDispenser(snippet)
		rw := &caddywarden.RouteWarden{}
		if err := rw.UnmarshalCaddyfile(d); err != nil {
			t.Fatalf("unexpected unmarshal error: %v", err)
		}
		if !rw.CheckBody {
			t.Errorf("expected CheckBody to be true")
		}
		if rw.CheckBodyMaxBytes != 32768 {
			t.Errorf("expected CheckBodyMaxBytes to be 32768, got %d", rw.CheckBodyMaxBytes)
		}
		if len(rw.CheckBodyPatterns) != 2 || rw.CheckBodyPatterns[0] != "(?i)grant_type=password" {
			t.Errorf("expected 2 CheckBodyPatterns, got %v", rw.CheckBodyPatterns)
		}
	})

	t.Run("enable_default_patterns and enable_default_allow_patterns directives", func(t *testing.T) {
		snippetFalse := `routewarden {
			enable_default_patterns false
			enable_default_allow_patterns false
			enabled false
		}`
		dFalse := caddyfile.NewTestDispenser(snippetFalse)
		rwFalse := &caddywarden.RouteWarden{}
		if err := rwFalse.UnmarshalCaddyfile(dFalse); err != nil {
			t.Fatalf("unexpected unmarshal error: %v", err)
		}
		if rwFalse.EnableDefaultPatterns {
			t.Errorf("expected EnableDefaultPatterns to be false")
		}
		if rwFalse.EnableDefaultAllowPatterns {
			t.Errorf("expected EnableDefaultAllowPatterns to be false")
		}
		if rwFalse.Enabled {
			t.Errorf("expected Enabled to be false")
		}

		snippetTrue := `routewarden {
			enable_default_patterns true
			enable_default_allow_patterns true
			enabled true
		}`
		dTrue := caddyfile.NewTestDispenser(snippetTrue)
		rwTrue := &caddywarden.RouteWarden{}
		if err := rwTrue.UnmarshalCaddyfile(dTrue); err != nil {
			t.Fatalf("unexpected unmarshal error: %v", err)
		}
		if !rwTrue.EnableDefaultPatterns {
			t.Errorf("expected EnableDefaultPatterns to be true")
		}
		if !rwTrue.EnableDefaultAllowPatterns {
			t.Errorf("expected EnableDefaultAllowPatterns to be true")
		}
		if !rwTrue.Enabled {
			t.Errorf("expected Enabled to be true")
		}
	})
}

func TestCaddyfile_MultipleBlockAndAllowPatterns(t *testing.T) {
	snippet := `routewarden {
		enabled true
		block_patterns (?i)^/admin/.*$ (?i)\.(key|pem)$
		block_patterns (?i)^/internal/metrics$
		allow_patterns (?i)^/admin/health$ (?i)^/admin/assets/.*$
		allow_patterns (?i)^/public/.*$
	}`
	d := caddyfile.NewTestDispenser(snippet)
	rw := &caddywarden.RouteWarden{}
	if err := rw.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	expectedBlocks := []string{
		`(?i)^/admin/.*$`,
		`(?i)\.(key|pem)$`,
		`(?i)^/internal/metrics$`,
	}
	if len(rw.BlockPatterns) != len(expectedBlocks) {
		t.Fatalf("expected %d BlockPatterns, got %d: %v", len(expectedBlocks), len(rw.BlockPatterns), rw.BlockPatterns)
	}
	for i, exp := range expectedBlocks {
		if rw.BlockPatterns[i] != exp {
			t.Errorf("BlockPatterns[%d] expected %q, got %q", i, exp, rw.BlockPatterns[i])
		}
	}

	expectedAllows := []string{
		`(?i)^/admin/health$`,
		`(?i)^/admin/assets/.*$`,
		`(?i)^/public/.*$`,
	}
	if len(rw.AllowPatterns) != len(expectedAllows) {
		t.Fatalf("expected %d AllowPatterns, got %d: %v", len(expectedAllows), len(rw.AllowPatterns), rw.AllowPatterns)
	}
	for i, exp := range expectedAllows {
		if rw.AllowPatterns[i] != exp {
			t.Errorf("AllowPatterns[%d] expected %q, got %q", i, exp, rw.AllowPatterns[i])
		}
	}

	// Verify provisioning compiles the regexes without error
	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
	if err := rw.Provision(ctx); err != nil {
		t.Fatalf("unexpected provision error: %v", err)
	}
}


