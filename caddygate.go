// Package caddygate provides Passkey based authentication for Caddy.
package caddygate

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
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
	sSlash = "/"
)

func init() {
	caddy.RegisterModule(&Gate{})
	caddy.RegisterModule(&GateServe{})
	caddy.RegisterModule(&GateGuard{})
	httpcaddyfile.RegisterHandlerDirective(sGate, parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder(sGate, httpcaddyfile.Before, "respond")
}

type Gate struct {
	app map[string]app.App
}

// CaddyModule returns the Caddy module information.
func (*Gate) CaddyModule() caddy.ModuleInfo {
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
func (*GateServe) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.gate.serve",
		New: func() caddy.Module { return new(GateServe) },
	}
}

func (g *GateServe) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// gate serve {block}
	// gate serve named {block}
	switch d.Token().Text {
	default:
		return d.Errf("unexpected %q", d.Token().Text)
	case sServe:
		if !d.NextArg() {
			return d.Err("must specify name after gate serve")
		}
		g.Name = d.Token().Text

		// look for immediate block to trigger serve for default config
		var foundImmediateBlock bool
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			foundImmediateBlock = true
			if err := unmarshalAppConfigLine(&g.Config, d); err != nil {
				return err
			}
		}
		if foundImmediateBlock {
			return nil
		} else {
			return d.Err("must specify block after gate serve <name>")
		}
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
func (*GateGuard) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.gate.guard",
		New: func() caddy.Module { return new(GateGuard) },
	}
}

func (g *GateGuard) UnmarshalCaddyfile(h *caddyfile.Dispenser) error {
	// gate / {tags}
	// gate guard named
	// gate guard named / {tags}
	switch h.Token().Text {
	default:
		return h.Errf("unexpected %q", h.Token().Text)
	case sSlash:
		g.Tags = h.RemainingArgs()
		if len(g.Tags) == 0 {
			return h.Err("must specify tags after slash")
		}
	case sGuard:
		if !h.NextArg() {
			return h.Err("must specify name after gate guard")
		}
		g.Name = h.Token().Text

		// if next arg, must be slash + tags
		if h.NextArg() {
			if h.Token().Text != sSlash {
				return h.Errf("expected slash and tags but got %q", h.Token().Text)
			}
			g.Tags = h.RemainingArgs()
			if len(g.Tags) == 0 {
				return h.Err("must specify tags after slash")
			}
		}
	}
	return nil
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

func nextArgString(dest *string, d *caddyfile.Dispenser) error {
	if !d.NextArg() {
		return d.ArgErr()
	}
	*dest = d.Token().Text
	return nil
}

func nextArgB64URL(dest *[]byte, d *caddyfile.Dispenser) error {
	if !d.NextArg() {
		return d.ArgErr()
	}
	b, err := base64.RawURLEncoding.DecodeString(d.Token().Text)
	if err != nil {
		return d.Errf("invalid base64 URL encoded string: %s", d.Token().Text)
	}
	*dest = b
	return nil
}

func nextArgDuration(dest *time.Duration, d *caddyfile.Dispenser) error {
	if !d.NextArg() {
		return d.ArgErr()
	}
	v, err := caddy.ParseDuration(d.Token().Text)
	if err != nil {
		return d.Errf("invalid duration string: %s", d.Token().Text)
	}
	*dest = v
	return nil
}

func unmarsalRpLine(c *app.Config, d *caddyfile.Dispenser) error {
	var err error
	switch d.Token().Text {
	default:
		return d.Errf("unexpected option in rp block: %s", d.Token().Text)
	case "display_name":
		err = nextArgString(&c.RP.DisplayName, d)
	case "id":
		err = nextArgString(&c.RP.ID, d)
	case "origin":
		if !d.NextArg() {
			return d.ArgErr()
		}
		c.RP.Origins = append(c.RP.Origins, d.Token().Text)
	}
	return err
}

func unmarshalAppConfigLine(c *app.Config, d *caddyfile.Dispenser) error {
	var err error
	switch d.Token().Text {
	default:
		return d.Errf("unexpected option in serve block: %s", d.Token().Text)
	case "users":
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			segment := d.NextSegment()
			if len(segment) == 0 {
				continue // empty line
			}
			var u app.User
			for i, token := range segment {
				switch i {
				default:
					u.Tags = append(u.Tags, token.Text)
				case 0:
					u.ID = token.Text
				case 1:
					u.Name = token.Text
				}
			}
			c.Users = append(c.Users, u)
		}
	case "rp":
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			if err := unmarsalRpLine(c, d); err != nil {
				return err
			}
		}
	case "auth_base_url":
		err = nextArgString(&c.AuthBaseURL, d)
	case "cookie_domain":
		err = nextArgString(&c.CookieDomain, d)
	case "cookie_name_prefix":
		err = nextArgString(&c.CookieNamePrefix, d)
	case "cookie_path":
		err = nextArgString(&c.CookiePath, d)
	case "data_dir":
		err = nextArgString(&c.DataDir, d)
	case "cookie_secret":
		err = nextArgB64URL(&c.CookieSecret, d)
	case "cookie_ttl":
		err = nextArgDuration(&c.CookieTTL, d)
	case "invite_ttl":
		err = nextArgDuration(&c.InviteTTL, d)
	}
	return err
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	h.Next() // consume "gate"

	// look for immediate block to trigger serve for default config
	var foundImmediateBlock bool
	var c app.Config
	for nesting := h.Nesting(); h.NextBlock(nesting); {
		foundImmediateBlock = true
		if err := unmarshalAppConfigLine(&c, h.Dispenser); err != nil {
			return nil, err
		}
	}
	if foundImmediateBlock {
		return &GateServe{Config: c}, nil
	}

	// bare "gate", implicit guard with default config
	if !h.NextArg() {
		return &GateGuard{}, nil
	}

	switch h.Token().Text {
	default:
		return nil, h.Errf("unexpected token %q", h.Token().Text)
	case sGuard, sSlash:
		// gate / {tags}
		// gate guard named
		// gate guard named / {tags}
		var g GateGuard
		if err := g.UnmarshalCaddyfile(h.Dispenser); err != nil {
			return nil, err
		}
		return &g, nil
	case sServe:
		// gate {block}
		// gate serve named {block}
		var g GateServe
		if err := g.UnmarshalCaddyfile(h.Dispenser); err != nil {
			return nil, err
		}
		return &g, nil
	}
}
