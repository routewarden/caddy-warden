package caddywarden

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
)

func TestParseCaddyfile(t *testing.T) {
	input := `routewarden {
		enabled false
	}`
	d := caddyfile.NewTestDispenser(input)
	helper := httpcaddyfile.Helper{
		Dispenser: d,
	}

	handler, err := parseCaddyfile(helper)
	if err != nil {
		t.Fatalf("unexpected error parsing caddyfile: %v", err)
	}

	rw, ok := handler.(*RouteWarden)
	if !ok {
		t.Fatalf("expected *RouteWarden returned from parseCaddyfile")
	}

	if rw.Enabled {
		t.Errorf("expected rw.Enabled to be false")
	}
}

func TestParseCaddyfile_RouteWardenDirective(t *testing.T) {
	input := `route_warden {
		enabled false
		block_patterns "/secret"
	}`
	d := caddyfile.NewTestDispenser(input)
	helper := httpcaddyfile.Helper{
		Dispenser: d,
	}

	handler, err := parseCaddyfile(helper)
	if err != nil {
		t.Fatalf("unexpected error parsing caddyfile with route_warden: %v", err)
	}

	rw, ok := handler.(*RouteWarden)
	if !ok {
		t.Fatalf("expected *RouteWarden returned from parseCaddyfile")
	}

	if rw.Enabled {
		t.Errorf("expected rw.Enabled to be false")
	}
	if len(rw.BlockPatterns) != 1 || rw.BlockPatterns[0] != "/secret" {
		t.Errorf("expected block_patterns to be ['/secret'], got %v", rw.BlockPatterns)
	}
}

func TestDirectiveOrderAdapt(t *testing.T) {
	adapter := caddyconfig.GetAdapter("caddyfile")
	if adapter == nil {
		t.Skip("caddyfile adapter not found")
	}

	// Test routewarden
	cfg1 := `
	:8080 {
		routewarden {
			block_patterns "/secret"
		}
		reverse_proxy localhost:9999
	}
	`
	out1, _, err1 := adapter.Adapt([]byte(cfg1), nil)
	if err1 != nil {
		t.Fatalf("unexpected adapt error for routewarden: %v", err1)
	}
	if !strings.Contains(string(out1), `"handler":"routewarden"`) {
		t.Errorf("expected output to contain routewarden handler, got: %s", string(out1))
	}

	// Test route_warden alias
	cfg2 := `
	:8080 {
		route_warden {
			block_patterns "/admin"
		}
		respond "hello"
	}
	`
	out2, _, err2 := adapter.Adapt([]byte(cfg2), nil)
	if err2 != nil {
		t.Fatalf("unexpected adapt error for route_warden: %v", err2)
	}
	if !strings.Contains(string(out2), `"handler":"routewarden"`) || !strings.Contains(string(out2), `"/admin"`) {
		t.Errorf("expected output to contain routewarden handler with /admin pattern, got: %s", string(out2))
	}
}

func TestUserConfig_BlocksDotEnv(t *testing.T) {
	adapter := caddyconfig.GetAdapter("caddyfile")
	cfg := `
{
    admin off
    order routewarden before reverse_proxy
}

(routewarden) {    
    routewarden {
        enable_default_allow_patterns true
        enable_default_patterns true
        response {
          mode redirect
          redirect_url "https://routewarden.github.io"
        }
    }
}

api.test.com {
    import routewarden
    encode zstd gzip
}
`
	out, warns, err := adapter.Adapt([]byte(cfg), nil)
	if err != nil {
		t.Fatalf("Adapt error: %v", err)
	}
	t.Logf("Adapt warns: %v", warns)

	var doc struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Routes []struct {
						Handle []struct {
							Handler string `json:"handler"`
							Routes  []struct {
								Handle []json.RawMessage `json:"handle"`
							} `json:"routes"`
						} `json:"handle"`
					} `json:"routes"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}

	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("json unmarshal error: %v", err)
	}

	var rw RouteWarden
	found := false
	for _, srv := range doc.Apps.HTTP.Servers {
		for _, r := range srv.Routes {
			for _, h := range r.Handle {
				for _, subR := range h.Routes {
					for _, subH := range subR.Handle {
						if strings.Contains(string(subH), `"handler":"routewarden"`) {
							if err := json.Unmarshal(subH, &rw); err != nil {
								t.Fatalf("failed to unmarshal RouteWarden: %v", err)
							}
							found = true
							break
						}
					}
				}
			}
		}
	}

	if !found {
		t.Fatalf("RouteWarden handler not found in adapted JSON: %s", string(out))
	}

	if err := rw.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision error: %v", err)
	}

	downstreamCalled := false
	downstream := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		downstreamCalled = true
		w.WriteHeader(http.StatusOK)
		return nil
	})

	// Test: curl http://api.test.com/.env
	req := httptest.NewRequest(http.MethodGet, "http://api.test.com/.env", nil)
	rec := httptest.NewRecorder()
	if err := rw.ServeHTTP(rec, req, downstream); err != nil {
		t.Fatalf("ServeHTTP error: %v", err)
	}

	if downstreamCalled {
		t.Errorf("expected downstream handler NOT to be called for /.env")
	}
	if rec.Code != http.StatusFound {
		t.Errorf("expected status %d, got %d", http.StatusFound, rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "https://routewarden.github.io" {
		t.Errorf("expected Location 'https://routewarden.github.io', got %q", loc)
	}
}

func TestHandleBehavior(t *testing.T) {
	adapter := caddyconfig.GetAdapter("caddyfile")
	cfg := `
{
    admin off
    order routewarden before handle
}

(routewarden) {    
    routewarden {
        enable_default_patterns true
    }
}

api.test.com {
    import routewarden

    handle {
        reverse_proxy localhost:8000
    }
}
`
	out, _, err := adapter.Adapt([]byte(cfg), nil)
	if err != nil {
		t.Fatalf("unexpected adapt error: %v", err)
	}
	routewardenIdx := strings.Index(string(out), `"handler":"routewarden"`)
	innerSubrouteIdx := strings.LastIndex(string(out), `"handler":"subroute"`)
	if routewardenIdx == -1 || innerSubrouteIdx == -1 || routewardenIdx > innerSubrouteIdx {
		t.Errorf("expected routewarden to appear before inner handle subroute, got routewardenIdx: %d, innerSubrouteIdx: %d", routewardenIdx, innerSubrouteIdx)
	}
}


