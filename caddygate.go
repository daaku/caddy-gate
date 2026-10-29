// Package caddygate provides Passkey based authentication for Caddy.
package caddygate

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
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

var (
	_ caddy.App         = (*Gate)(nil)
	_ caddy.Provisioner = (*Gate)(nil)
)

func init() {
	caddy.RegisterModule(&Gate{})
	caddy.RegisterModule(&GateServe{})
	caddy.RegisterModule(&GateGuard{})
	httpcaddyfile.RegisterHandlerDirective(sGate,
		func(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
			return parseCaddyfile(h.Dispenser)
		})
	httpcaddyfile.RegisterDirectiveOrder(sGate, httpcaddyfile.Before, "respond")
	httpcaddyfile.RegisterGlobalOption(sGate, parseGlobalOption)
}

// describe names the gate config for use in error messages.
func describe(name string) string {
	if name == "" {
		return "default gate"
	}
	return fmt.Sprintf("gate %q", name)
}

type Gate struct {
	// Configs are the shared configs from the gate global option, keyed by
	// name. These are needed on every machine with a guard or serve.
	Configs map[string]app.Config `json:"configs,omitempty"`

	verifiers map[string]*app.Verifier
	served    map[string]bool
	guarded   []string
}

// CaddyModule returns the Caddy module information.
func (*Gate) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  appID,
		New: func() caddy.Module { return new(Gate) },
	}
}

// Provision builds the verifiers for the global configs.
func (g *Gate) Provision(ctx caddy.Context) error {
	g.verifiers = make(map[string]*app.Verifier)
	g.served = make(map[string]bool)
	for name, c := range g.Configs {
		v, err := app.NewVerifier(c)
		if err != nil {
			return fmt.Errorf("%s: %w", describe(name), err)
		}
		g.verifiers[name] = v
	}
	return nil
}

// Start and Stop causes us to implement `caddy.App` and ensures our instance
// gets cached on `ctx.App` use, which is required for `GateGuard` to access
// the configuration. Start runs after all modules have been provisioned, so
// it's where guards without a config are caught. This includes configs given
// inline to a serve, which are only known once that serve is provisioned.
func (g *Gate) Start() error {
	for _, name := range g.guarded {
		if g.verifiers[name] == nil {
			return fmt.Errorf("%s guard used without defining the %s config", describe(name), describe(name))
		}
	}
	return nil
}

func (g *Gate) Stop() error {
	return nil
}

type GateServe struct {
	Name string `json:"name,omitempty" caddydecl:"serve"`
	// Config is only set when the shared config is given inline, instead of
	// with the gate global option.
	*app.Config     `json:"config,omitempty"`
	app.ServeConfig `json:"serve"`

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
	return g.provision(gate)
}

// provision uses the global config if one exists, or else the inline one, and
// makes it available to guards.
func (g *GateServe) provision(gate *Gate) error {
	if gate.served[g.Name] {
		return fmt.Errorf("%s serve redefined", describe(g.Name))
	}

	var c app.Config
	if global, found := gate.Configs[g.Name]; found {
		if g.Config != nil {
			return fmt.Errorf("%s config defined both globally and inline in serve", describe(g.Name))
		}
		c = global
	} else if g.Config != nil {
		c = *g.Config
	} else {
		return fmt.Errorf("%s serve used without defining the %s config", describe(g.Name), describe(g.Name))
	}

	var err error
	g.app, err = app.NewApp(c, g.ServeConfig)
	if err != nil {
		return err
	}

	gate.served[g.Name] = true
	gate.verifiers[g.Name] = g.app.Verifier()

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

	gate     *Gate
	verifier *app.Verifier
	once     sync.Once
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
	g.gate.guarded = append(g.gate.guarded, g.Name)
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
	// Looked up on first use, since a config given inline to a serve is only
	// known once that serve is provisioned.
	g.once.Do(func() {
		g.verifier = g.gate.verifiers[g.Name]
	})
	if g.verifier == nil {
		return fmt.Errorf("%s guard used without defining the %s config", describe(g.Name), describe(g.Name))
	}
	u, err := g.verifier.CurrentUser(w, r)
	if app.IsNotSignedInError(err) {
		// Build the full URL of the page being protected. For origin-form
		// requests r.URL only carries the path, so fill in the scheme and
		// host. For absolute-form requests (as sent by proxies) r.URL is
		// already complete and must not be prefixed again or the host ends
		// up duplicated.
		nextURL := *r.URL
		if nextURL.Scheme == "" {
			nextURL.Scheme = "https"
		}
		if nextURL.Host == "" {
			nextURL.Host = r.Host
		}
		next, err := g.verifier.SealNextURL(nextURL.String())
		if err != nil {
			return fmt.Errorf("unable to seal next url: %w", err)
		}
		signInURL := fmt.Sprintf("%s?next=%s", g.verifier.SignInURL(), url.QueryEscape(next))
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

	g.verifier.StripCookies(r)

	const kHeaderUserID = "X-Caddy-Gate-User-ID"
	delHeaderVariants(r.Header, kHeaderUserID)
	if g.HeaderUserID {
		r.Header.Set(kHeaderUserID, u.ID)
	}

	const kHeaderUserTags = "X-Caddy-Gate-User-Tags"
	delHeaderVariants(r.Header, kHeaderUserTags)
	if g.HeaderUserTags && len(u.Tags) > 0 {
		r.Header.Set(kHeaderUserTags, strings.Join(u.Tags, ","))
	}
	return next.ServeHTTP(w, r)
}

// delHeaderVariants removes every header a backend could read as name. That
// includes spellings with underscores in place of dashes, since CGI and FastCGI
// (including Caddy's own php_fastcgi) map both to the same variable.
func delHeaderVariants(h http.Header, name string) {
	for k := range h {
		if strings.EqualFold(strings.ReplaceAll(k, "_", "-"), name) {
			delete(h, k)
		}
	}
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
		// gate {block}
		// gate serve {block}
		// gate serve {named} {block}
		if d.Val() == sServe && d.Next() && d.Val() == "{" {
			// the default serve, drop the "serve" so it isn't missing a name
			d.Reset()
			d.Next()
			segment := d.NextSegment()
			d = caddyfile.NewDispenser(slices.Delete(segment, 1, 2))
		}
		d.Reset()
		var s GateServe
		if err := caddydecl.Unmarshal(&s, d); err != nil {
			return nil, err
		}
		return &s, nil
	}
}

// globalOption is one gate global option, holding the shared config, which
// guards need on every machine:
//
//	gate [name] {block}
type globalOption struct {
	Name string `caddydecl:"arg=0"`
	app.Config
}

// parseGlobalOption parses a gate global option. Caddy calls it once for each
// gate global option, passing what it returned for the previous one as
// existing (nil for the first). That's how multiple named configs accumulate
// into the one gate app, which Caddy only accepts as JSON.
func parseGlobalOption(d *caddyfile.Dispenser, existing any) (any, error) {
	gate, err := gateFromOption(existing)
	if err != nil {
		return nil, d.WrapErr(err)
	}
	var opt globalOption
	if err := caddydecl.Unmarshal(&opt, d); err != nil {
		return nil, err
	}
	if _, found := gate.Configs[opt.Name]; found {
		return nil, d.Errf("%s config redefined", describe(opt.Name))
	}
	if gate.Configs == nil {
		gate.Configs = make(map[string]app.Config)
	}
	gate.Configs[opt.Name] = opt.Config
	return httpcaddyfile.App{Name: appID, Value: caddyconfig.JSON(gate, nil)}, nil
}

// gateFromOption decodes the gate app that parseGlobalOption returned for the
// previous gate global option, if any.
func gateFromOption(existing any) (Gate, error) {
	var gate Gate
	if existing == nil {
		return gate, nil
	}
	existingApp, ok := existing.(httpcaddyfile.App)
	if !ok {
		return gate, fmt.Errorf("existing %s option of unexpected type: %T", sGate, existing)
	}
	err := json.Unmarshal(existingApp.Value, &gate)
	return gate, err
}
