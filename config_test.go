package caddywarden_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	caddywarden "github.com/routewarden/caddy-warden"
)

// CF-1: Valid JSON config file loads all base fields
func TestConfigFile_LoadsValidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "routewarden.json")
	jsonContent := `{
		"enabled": true,
		"enableDefaultPatterns": false,
		"enableDefaultAllowPatterns": true,
		"blockPatterns": ["(?i)^/secret-from-file$"],
		"allowedIps": ["10.0.0.0/8"],
		"statusCode": 403,
		"response": {
			"mode": "json",
			"body": "{\"error\":\"File Blocked\"}"
		}
	}`
	if err := os.WriteFile(cfgFile, []byte(jsonContent), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	rw := &caddywarden.RouteWarden{
		ConfigFile: cfgFile,
	}

	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
	if err := rw.Provision(ctx); err != nil {
		t.Fatalf("provision failed: %v", err)
	}

	if rw.EnableDefaultPatterns {
		t.Errorf("expected EnableDefaultPatterns=false from file")
	}
	if len(rw.BlockPatterns) != 1 || rw.BlockPatterns[0] != "(?i)^/secret-from-file$" {
		t.Errorf("expected block patterns from file, got %v", rw.BlockPatterns)
	}

	// Test handler execution
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/secret-from-file", nil)
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})

	if err := rw.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("unexpected handler error: %v", err)
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"error":"File Blocked"`) {
		t.Errorf("expected custom JSON body from file, got %s", rec.Body.String())
	}
}

// CF-2: Missing file returns descriptive error
func TestConfigFile_MissingFile(t *testing.T) {
	rw := &caddywarden.RouteWarden{
		ConfigFile: "/nonexistent/path/routewarden.json",
	}
	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
	err := rw.Provision(ctx)
	if err == nil {
		t.Fatal("expected error for missing config file, got nil")
	}
	if !strings.Contains(err.Error(), "cannot read config_file") {
		t.Errorf("expected 'cannot read config_file' in error message, got: %v", err)
	}
}

// CF-3: Malformed JSON returns descriptive error
func TestConfigFile_MalformedJSON(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "broken.json")
	if err := os.WriteFile(cfgFile, []byte("{ this is not json }"), 0644); err != nil {
		t.Fatal(err)
	}

	rw := &caddywarden.RouteWarden{
		ConfigFile: cfgFile,
	}
	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
	err := rw.Provision(ctx)
	if err == nil {
		t.Fatal("expected error for malformed json, got nil")
	}
	if !strings.Contains(err.Error(), "cannot parse config_file") {
		t.Errorf("expected 'cannot parse config_file' in error message, got: %v", err)
	}
}

// CF-4: Empty JSON object preserves defaults
func TestConfigFile_EmptyObject(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "empty.json")
	if err := os.WriteFile(cfgFile, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}

	rw := &caddywarden.RouteWarden{
		ConfigFile: cfgFile,
	}
	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
	if err := rw.Provision(ctx); err != nil {
		t.Fatalf("unexpected provision error: %v", err)
	}
	if !rw.Enabled {
		t.Errorf("expected Enabled to default to true")
	}
}

// CF-5: Inline values override file settings
func TestConfigFile_InlineOverridesFile(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "base.json")
	jsonContent := `{
		"statusCode": 403,
		"blockPatterns": ["(?i)^/from-file$"],
		"enableDefaultPatterns": false
	}`
	if err := os.WriteFile(cfgFile, []byte(jsonContent), 0644); err != nil {
		t.Fatal(err)
	}

	rw := &caddywarden.RouteWarden{
		ConfigFile:    cfgFile,
		StatusCode:    429,
		BlockPatterns: []string{"(?i)^/from-inline$"},
	}
	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
	if err := rw.Provision(ctx); err != nil {
		t.Fatalf("provision failed: %v", err)
	}

	if rw.StatusCode != 429 {
		t.Errorf("expected inline StatusCode=429 to override file 403, got %d", rw.StatusCode)
	}
	if len(rw.BlockPatterns) != 1 || rw.BlockPatterns[0] != "(?i)^/from-inline$" {
		t.Errorf("expected inline BlockPatterns to override file, got %v", rw.BlockPatterns)
	}
}

// CF-6: Empty string ConfigFile is a no-op
func TestConfigFile_EmptyConfigFilePathIsNoOp(t *testing.T) {
	rw := &caddywarden.RouteWarden{
		ConfigFile: "",
	}
	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
	if err := rw.Provision(ctx); err != nil {
		t.Fatalf("unexpected error with empty ConfigFile: %v", err)
	}
}

// CF-7: Unknown JSON keys are safely ignored
func TestConfigFile_UnknownJSONKeys(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "extra.json")
	jsonContent := `{
		"unknownProperty": 12345,
		"extraKey": "value",
		"enabled": true
	}`
	if err := os.WriteFile(cfgFile, []byte(jsonContent), 0644); err != nil {
		t.Fatal(err)
	}

	rw := &caddywarden.RouteWarden{
		ConfigFile: cfgFile,
	}
	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
	if err := rw.Provision(ctx); err != nil {
		t.Fatalf("unexpected error with extra keys: %v", err)
	}
}

// CF-8: Directory path passed as ConfigFile returns read error
func TestConfigFile_DirectoryPathError(t *testing.T) {
	tmpDir := t.TempDir()
	rw := &caddywarden.RouteWarden{
		ConfigFile: tmpDir,
	}
	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
	err := rw.Provision(ctx)
	if err == nil {
		t.Fatal("expected error when ConfigFile is a directory, got nil")
	}
}

// CF-9: 0-byte file returns parse error
func TestConfigFile_ZeroByteFile(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "zero.json")
	if err := os.WriteFile(cfgFile, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	rw := &caddywarden.RouteWarden{
		ConfigFile: cfgFile,
	}
	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
	err := rw.Provision(ctx)
	if err == nil {
		t.Fatal("expected error for 0-byte file, got nil")
	}
}

// CF-10: Snake_case response fields parsed correctly from ConfigFile
func TestConfigFile_SnakeCaseResponseConfig(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "snake_resp.json")
	jsonContent := `{
		"status_code": 404,
		"methods": ["GET", "POST"],
		"security_log": false,
		"response": {
			"mode": "redirect",
			"status_code": 301,
			"redirect_url": "https://example.com/blocked",
			"content_type": "text/html"
		}
	}`
	if err := os.WriteFile(cfgFile, []byte(jsonContent), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	rw := &caddywarden.RouteWarden{
		ConfigFile: cfgFile,
	}
	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
	if err := rw.Provision(ctx); err != nil {
		t.Fatalf("unexpected provision error: %v", err)
	}

	if rw.StatusCode != 404 {
		t.Errorf("expected StatusCode 404, got %d", rw.StatusCode)
	}
	if rw.Response == nil {
		t.Fatal("expected Response to be non-nil")
	}
	if rw.Response.StatusCode != 301 {
		t.Errorf("expected Response.StatusCode 301, got %d", rw.Response.StatusCode)
	}
	if rw.Response.RedirectURL != "https://example.com/blocked" {
		t.Errorf("expected Response.RedirectURL 'https://example.com/blocked', got %q", rw.Response.RedirectURL)
	}
	if rw.Response.ContentType != "text/html" {
		t.Errorf("expected Response.ContentType 'text/html', got %q", rw.Response.ContentType)
	}
}

// H-1 & H-3: Concurrent requests (100 goroutines) with -race
func TestRouteWarden_ConcurrentRequests(t *testing.T) {
	rw := &caddywarden.RouteWarden{
		BlockPatterns: []string{"(?i)^/admin/.*$"},
		AllowedIPs:    []string{"192.168.1.100"},
		CheckQuery:    true,
	}
	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
	if err := rw.Provision(ctx); err != nil {
		t.Fatalf("provision failed: %v", err)
	}

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})

	var wg sync.WaitGroup
	workers := 100

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			rec := httptest.NewRecorder()
			var req *http.Request
			if id%2 == 0 {
				req = httptest.NewRequest(http.MethodGet, "/admin/dashboard", nil)
				req.RemoteAddr = "10.0.0.1:12345"
			} else {
				req = httptest.NewRequest(http.MethodGet, "/public/api/health", nil)
				req.RemoteAddr = "192.168.1.100:12345"
			}
			_ = rw.ServeHTTP(rec, req, next)
		}(i)
	}

	wg.Wait()
}

// H-7: Double Provision() call is idempotent
func TestRouteWarden_DoubleProvision(t *testing.T) {
	rw := &caddywarden.RouteWarden{
		BlockPatterns: []string{"(?i)^/test$"},
	}
	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
	if err := rw.Provision(ctx); err != nil {
		t.Fatalf("first provision failed: %v", err)
	}
	if err := rw.Provision(ctx); err != nil {
		t.Fatalf("second provision failed: %v", err)
	}
}
