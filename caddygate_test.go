package caddygate

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/daaku/ensure"
)

func h(v string) httpcaddyfile.Helper {
	return httpcaddyfile.Helper{}.WithDispenser(caddyfile.NewTestDispenser(v))
}

func TestBareGate(t *testing.T) {
	v, err := parseCaddyfile(h(`gate`))
	ensure.Nil(t, err)
	ensure.DeepEqual(t, v, &GateGuard{})
}

// func TestNamedGuard(t *testing.T) {
// 	v, err := parseCaddyfile(h(`gate guard example.com`))
// 	ensure.Nil(t, err)
// 	ensure.DeepEqual(t, v, &GateGuard{})
// }

func TestDefaultGuardWithSingleTag(t *testing.T) {
	v, err := parseCaddyfile(h(`gate / admin`))
	ensure.Nil(t, err)
	ensure.DeepEqual(t, v, &GateGuard{Tags: []string{"admin"}})
}

func TestDefaultGuardWithMultipleTags(t *testing.T) {
	v, err := parseCaddyfile(h(`gate / admin crew`))
	ensure.Nil(t, err)
	ensure.DeepEqual(t, v, &GateGuard{Tags: []string{"admin", "crew"}})
}
