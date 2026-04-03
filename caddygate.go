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
	appID          = "gate"
	caddyDirective = "gate"
)

func init() {
	caddy.RegisterModule(Gate{})
	caddy.RegisterModule(GateServe{})
	caddy.RegisterModule(GateGuard{})
	httpcaddyfile.RegisterHandlerDirective(caddyDirective, parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder(caddyDirective, httpcaddyfile.Before, "respond")
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
	// gate {block}
	// gate serve named {block}
	//
	// gate
	// gate guard named
	// gate [tags]
	// gate guard named [tags]
	panic("unimplemented")
}
