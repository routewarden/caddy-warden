package caddywarden

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
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

