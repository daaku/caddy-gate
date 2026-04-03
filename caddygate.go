// Package caddygate provides Passkey based authentication for Caddy.
package caddygate

import (
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/daaku/caddygate/app"
)

const (
	// app id for shared state
	appID = "gate"

	// caddyfile syntax elements
	sGate  = "gate"
	sServe = "serve"
	sGuard = "guard"
)

func init() {
	caddy.RegisterModule(Gate{})
	caddy.RegisterModule(GateServe{})
	caddy.RegisterModule(GateGuard{})
	httpcaddyfile.RegisterHandlerDirective(sGate, parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder(sGate, httpcaddyfile.Before, "respond")
}

type Gate struct {
	app map[string]app.App
}

// CaddyModule returns the Caddy module information.
func (Gate) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  appID,
		New: func() caddy.Module { return new(Gate) },
	}
}

func (g *Gate) Provision(ctx caddy.Context) error {
	return nil
}

type GateServe struct {
	Name   string     `json:"name,omitempty"`
	Config app.Config `json:"config"`
}

// CaddyModule returns the Caddy module information.
func (GateServe) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.gate.serve",
		New: func() caddy.Module { return new(GateServe) },
	}
}

func (g *GateServe) parseCaddyfile(h httpcaddyfile.Helper) error {
	// gate serve {block}
	// gate serve named {block}
	panic("unimplemented")
}

// Provision provisions Gate Serve.
func (g *GateServe) Provision(ctx caddy.Context) error {
	appModule, err := ctx.App(appID)
	if err != nil {
		return err
	}

	gate := appModule.(*Gate)
	if gate == nil {
		return fmt.Errorf("%s app is nil", appID)
	}
	return nil
}

// Validate implements caddy.Validator.
func (g *GateServe) Validate() error {
	return nil
}

// ServeHTTP serves the Gate UI.
func (g *GateServe) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	panic("unimplemented")
}

type GateGuard struct {
	Name string   `json:"name,omitempty"`
	Tags []string `json:"tags,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (GateGuard) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.gate.guard",
		New: func() caddy.Module { return new(GateGuard) },
	}
}

func (g *GateGuard) parseCaddyfile(h httpcaddyfile.Helper) error {
	// gate guard {tags}
	// gate guard named
	// gate guard named {tags}
	panic("unimplemented")
}

// Provision provisions Gate Serve.
func (g *GateGuard) Provision(ctx caddy.Context) error {
	appModule, err := ctx.App(appID)
	if err != nil {
		return err
	}

	gate := appModule.(*Gate)
	if gate == nil {
		return fmt.Errorf("%s app is nil", appID)
	}
	return nil
}

// Validate implements caddy.Validator.
func (g *GateGuard) Validate() error {
	return nil
}

// ServeHTTP serves the Gate UI.
func (g *GateGuard) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	panic("unimplemented")
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	// bare "gate"
	if !h.NextArg() {
		return &GateGuard{}, nil
	}
	// TODO error if have a block here

	switch h.Token().Text {
	default:
		return nil, h.Errf("unexpected token %q", h.Token().Text)
	case sGuard:
		// gate guard {tags}
		// gate guard named
		// gate guard named {tags}
		var g GateGuard
		return &g, g.parseCaddyfile(h)
	case sServe:
		// gate serve {block}
		// gate serve named {block}
		var g GateServe
		return &g, g.parseCaddyfile(h)
	}
}
