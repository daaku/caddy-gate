// Package caddygate provides Passkey based authentication for Caddy.
package caddygate

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/daaku/caddy-gate/internal/app"
	"github.com/daaku/caddydecl"
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
	httpcaddyfile.RegisterHandlerDirective(sGate,
		func(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
			return parseCaddyfile(h.Dispenser)
		})
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
	Name       string `json:"name,omitempty" caddydecl:"serve"`
	app.Config `json:"config"`

	app *app.App
}

// CaddyModule returns the Caddy module information.
func (*GateServe) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.gate-serve",
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
}

type GateGuard struct {
	Name           string   `json:"name,omitempty" caddydecl:"guard"`
	Tags           []string `json:"tags,omitempty" caddydecl:"with"`
	HeaderUserID   bool     `json:"headerUserID,omitempty"`
	HeaderUserTags bool     `json:"headerUserTags,omitempty"`

	gate *Gate
	app  *app.App
	once sync.Once
}

// CaddyModule returns the Caddy module information.
func (*GateGuard) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.gate-guard",
		New: func() caddy.Module { return new(GateGuard) },
	}
}

// Provision provisions Gate Serve.
func (g *GateGuard) Provision(ctx caddy.Context) error {
	appModule, err := ctx.App(appID)
	if err != nil {
		return err
	}

	g.gate = appModule.(*Gate)
	if g.gate == nil {
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
	g.once.Do(func() {
		g.app = g.gate.app[g.Name]
	})
	if g.app == nil {
		if g.Name == "" {
			return fmt.Errorf("default gate guard used without defining associated default serve")
		} else {
			return fmt.Errorf("named gate guard %q used without defining associated named serve", g.Name)
		}
	}
	u, err := g.app.CurrentUser(w, r)
	if app.IsNotSignedInError(err) {
		scheme := r.URL.Scheme
		if scheme == "" {
			scheme = "https"
		}
		next, err := g.app.SealNextURL(fmt.Sprintf("%s://%s%s",
			scheme, r.Host, r.URL.String()))
		if err != nil {
			return fmt.Errorf("unable to seal next url: %w", err)
		}
		signInURL := fmt.Sprintf("%s?next=%s", g.app.Config.SignInURL, url.QueryEscape(next))
		http.Redirect(w, r, signInURL, http.StatusSeeOther)
		return nil
	}
	if err != nil {
		return err
	}
	if !g.IsAllowed(u) {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, "You are logged in, but not allowed to access this.")
		return nil
	}

	const kHeaderUserID = "X-Caddy-Gate-User-ID"
	if g.HeaderUserID {
		r.Header.Set(kHeaderUserID, u.ID)
	} else {
		r.Header.Del(kHeaderUserID)
	}

	const kHeaderUserTags = "X-Caddy-Gate-User-Tags"
	if g.HeaderUserTags && len(u.Tags) > 0 {
		r.Header.Set(kHeaderUserTags, strings.Join(u.Tags, ","))
	} else {
		r.Header.Del(kHeaderUserTags)
	}
	return next.ServeHTTP(w, r)
}

func parseCaddyfile(d *caddyfile.Dispenser) (caddyhttp.MiddlewareHandler, error) {
	d.Next() // consume "gate"
	if !d.Next() {
		// bare "gate", guard with default config
		return &GateGuard{}, nil
	}
	switch d.Val() {
	default:
		return nil, d.Errf("unexpected argument: %q", d.Val())
	case sGuard, sWith:
		// gate with {tags}
		// gate guard {named}
		// gate guard {named} with {tags}
		d.Reset()
		var g GateGuard
		if err := caddydecl.Unmarshal(&g, d); err != nil {
			return nil, err
		}
		return &g, nil
	case "{", sServe:
		d.Reset()
		// gate {block}
		// gate serve {named} {block}
		var s GateServe
		if err := caddydecl.Unmarshal(&s, d); err != nil {
			return nil, err
		}
		return &s, nil
	}
}
