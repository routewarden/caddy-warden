package caddywarden

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

func TestParseCaddyfile(t *testing.T) {
	input := `routewarden {
		disable
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
