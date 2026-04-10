// Package caddygate provides Passkey based authentication for Caddy.
package caddygate

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/daaku/caddy-gate/internal/app"
)

const (
	// app id for shared state
	appID = "gate"

	// caddyfile syntax elements
	sGate  = "gate"
	sServe = "serve"
	sGuard = "guard"
	sWith  = "with"
)

var _ caddy.App = (*Gate)(nil)

func init() {
	caddy.RegisterModule(&Gate{})
	caddy.RegisterModule(&GateServe{})
	caddy.RegisterModule(&GateGuard{})
	httpcaddyfile.RegisterHandlerDirective(sGate, parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder(sGate, httpcaddyfile.Before, "respond")
}

type Gate struct {
	app map[string]*app.App
}

// CaddyModule returns the Caddy module information.
func (*Gate) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  appID,
		New: func() caddy.Module { return new(Gate) },
	}
}

// Start and Stop causes us to implement `caddy.App` and ensures our instance
// gets cached on `ctx.App` use, which is required for `GateGuard` to access
// `GateServe` configuration.
func (g *Gate) Start() error {
	return nil
}

func (g *Gate) Stop() error {
	return nil
}

type GateServe struct {
	Name   string     `json:"name,omitempty"`
	Config app.Config `json:"config"`

	app *app.App
}

// CaddyModule returns the Caddy module information.
func (*GateServe) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.gate-serve",
		New: func() caddy.Module { return new(GateServe) },
	}
}

func (g *GateServe) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	// gate serve {block}
	// gate serve named {block}
	switch d.Token().Text {
	default:
		return d.Errf("unexpected gate serve token: %q", d.Token().Text)
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

	if _, found := gate.app[g.Name]; found {
		if g.Name == "" {
			return fmt.Errorf("default gate serve redefined")
		} else {
			return fmt.Errorf("named gate serve %q redefined", g.Name)
		}
	}

	g.app, err = app.NewApp(g.Config)
	if err != nil {
		return err
	}

	if gate.app == nil {
		gate.app = make(map[string]*app.App)
	}
	gate.app[g.Name] = g.app

	return nil
}

// ServeHTTP serves the Gate UI.
func (g *GateServe) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	g.app.ServeHTTP(w, r)
	return nil
	// // TODO
	// io.WriteString(w, "hello from gate serve\n")
	// return nil
}

type GateGuard struct {
	Name string   `json:"name,omitempty"`
	Tags []string `json:"tags,omitempty"`

	g *Gate
	a *app.App
	o sync.Once
}

// CaddyModule returns the Caddy module information.
func (*GateGuard) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.gate-guard",
		New: func() caddy.Module { return new(GateGuard) },
	}
}

func (g *GateGuard) UnmarshalCaddyfile(h *caddyfile.Dispenser) error {
	// gate with {tags}
	// gate guard {named}
	// gate guard {named} with {tags}
	h.Next()
	switch h.Token().Text {
	default:
		return h.Errf("unexpected gate guard token: %q", h.Token().Text)
	case sWith:
		g.Tags = h.RemainingArgs()
		if len(g.Tags) == 0 {
			return h.Err("must specify tags after with")
		}
	case sGuard:
		if !h.NextArg() {
			return h.Err("must specify name after gate guard")
		}
		g.Name = h.Token().Text

		// if next arg, must be with + tags
		if h.NextArg() {
			if h.Token().Text != sWith {
				return h.Errf("expected with and tags but got %q", h.Token().Text)
			}
			g.Tags = h.RemainingArgs()
			if len(g.Tags) == 0 {
				return h.Err("must specify tags after with")
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

	g.g = appModule.(*Gate)
	if g.g == nil {
		return fmt.Errorf("%s app is nil", appID)
	}
	return nil
}

func (g *GateGuard) IsAllowed(u app.User) bool {
	if len(g.Tags) == 0 { // no tags required, any user ok
		return true
	}
	for _, tag := range g.Tags {
		if slices.Contains(u.Tags, tag) {
			return true
		}
	}
	return false
}

// ServeHTTP serves the Gate UI.
func (g *GateGuard) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	g.o.Do(func() {
		g.a = g.g.app[g.Name]
	})
	if g.a == nil {
		if g.Name == "" {
			return fmt.Errorf("default gate guard used without defining associated default serve")
		} else {
			return fmt.Errorf("named gate guard %q used without defining associated named serve", g.Name)
		}
	}
	u, err := g.a.CurrentUser(r)
	if app.IsNotSignedInError(err) {
		scheme := r.URL.Scheme
		if scheme == "" {
			scheme = "https"
		}
		next, err := g.a.SealNextURL(fmt.Sprintf("%s://%s%s",
			scheme, r.Host, r.URL.String()))
		if err != nil {
			return fmt.Errorf("unable to seal next url: %w", err)
		}
		signInURL := fmt.Sprintf("%s?next=%s", g.a.Config.SignInURL, url.QueryEscape(next))
		http.Redirect(w, r, signInURL, http.StatusSeeOther)
		return nil
	}
	if !g.IsAllowed(u) {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, "You are logged in, but not allowed to access this.")
		return nil
	}
	if err != nil {
		return err
	}
	return next.ServeHTTP(w, r)
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
				case 0:
					u.ID = token.Text
				case 1:
					u.Name = token.Text
				default:
					u.Tags = append(u.Tags, token.Text)
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
	case "secret":
		err = nextArgB64URL(&c.Secret, d)
	case "auth_base_url":
		err = nextArgString(&c.AuthBaseURL, d)
	case "sign_in_url":
		err = nextArgString(&c.SignInURL, d)
	case "default_next":
		err = nextArgString(&c.DefaultNext, d)
	case "cookie_domain":
		err = nextArgString(&c.CookieDomain, d)
	case "cookie_name_prefix":
		err = nextArgString(&c.CookieNamePrefix, d)
	case "cookie_path":
		err = nextArgString(&c.CookiePath, d)
	case "data_dir":
		err = nextArgString(&c.DataDir, d)
	case "cookie_ttl":
		err = nextArgDuration(&c.CookieTTL, d)
	case "invite_ttl":
		err = nextArgDuration(&c.InviteTTL, d)
	}
	return err
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	segment := h.NextSegment()
	segment = segment[2:] // consume empty start token and "gate"

	d := caddyfile.NewDispenser(segment)
	switch segment.Directive() {
	default:
		return nil, d.Errf("unable to identify serve or guard with: %q", d.Token().Text)
	case "":
		// bare "gate", guard with default config
		return &GateGuard{}, nil
	case "{":
		// bare "serve block", serve with default config
		var c app.Config
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			if err := unmarshalAppConfigLine(&c, d); err != nil {
				return nil, err
			}
		}
		return &GateServe{Config: c}, nil
	case sGuard, sWith:
		// gate / {tags}
		// gate guard {named}
		// gate guard {named} / {tags}
		var g GateGuard
		if err := g.UnmarshalCaddyfile(d); err != nil {
			return nil, err
		}
		return &g, nil
	case sServe:
		// gate {block}
		// gate serve {named} {block}
		var g GateServe
		if err := g.UnmarshalCaddyfile(d); err != nil {
			return nil, err
		}
		return &g, nil
	}
}
