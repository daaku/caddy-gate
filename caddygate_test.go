package caddygate

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/daaku/ensure"
)

func h(v string) httpcaddyfile.Helper {
	return httpcaddyfile.Helper{}.WithDispenser(caddyfile.NewTestDispenser(v))
}

func TestSuccessParseCaddyfile(t *testing.T) {
	cases := []struct {
		name, input string
		expected    caddyhttp.MiddlewareHandler
	}{
		{
			"bare gate guard",
			`gate`,
			&GateGuard{},
		},
		{
			"default gate guard with single tag",
			`gate / admin`,
			&GateGuard{Tags: []string{"admin"}},
		},
		{
			"default gate guard with multiple tags",
			`gate / admin crew`,
			&GateGuard{Tags: []string{"admin", "crew"}},
		},
		{
			"named gate guard with no tag",
			`gate guard example.com`,
			&GateGuard{Name: "example.com"},
		},
		{
			"named gate guard with single tag",
			`gate guard example.com / admin`,
			&GateGuard{
				Name: "example.com",
				Tags: []string{"admin"},
			},
		},
		{
			"named gate guard with single tag",
			`gate guard example.com / admin crew`,
			&GateGuard{
				Name: "example.com",
				Tags: []string{"admin", "crew"},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			actual, err := parseCaddyfile(h(c.input))
			ensure.Nil(t, err)
			ensure.DeepEqual(t, actual, c.expected)
		})
	}
}

func TestErrorParseCaddyfile(t *testing.T) {
	cases := []struct{ name, input, err string }{
		{
			"gate guard missing name",
			`gate guard`,
			"followed by name",
		},
		{
			"default gate with slash and no tags",
			`gate /`,
			"must specify tags",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			actual, err := parseCaddyfile(h(c.input))
			ensure.Nil(t, actual)
			ensure.StringContains(t, err.Error(), c.err)
		})
	}
}
