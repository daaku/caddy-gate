package caddygate

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/daaku/caddy-gate/internal/app"
	"github.com/daaku/ensure"
	"github.com/daaku/sookie"
)

func TestSuccessParseCaddyfile(t *testing.T) {
	cookieSecret := make([]byte, 32)
	rand.Read(cookieSecret)
	cookieSecretB64 := base64.RawURLEncoding.EncodeToString(cookieSecret)

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
			`gate with admin`,
			&GateGuard{Tags: []string{"admin"}},
		},
		{
			"default gate guard with multiple tags",
			`gate with admin crew`,
			&GateGuard{Tags: []string{"admin", "crew"}},
		},
		{
			"named gate guard with no tag",
			`gate guard example.com`,
			&GateGuard{Name: "example.com"},
		},
		{
			"named gate guard with single tag",
			`gate guard example.com with admin`,
			&GateGuard{
				Name: "example.com",
				Tags: []string{"admin"},
			},
		},
		{
			"named gate guard with multiple tags",
			`gate guard example.com with admin crew`,
			&GateGuard{
				Name: "example.com",
				Tags: []string{"admin", "crew"},
			},
		},
		{
			"default gate guard with block",
			`gate with admin crew {
				header_user_id true
			}`,
			&GateGuard{
				Tags:         []string{"admin", "crew"},
				HeaderUserID: true,
			},
		},
		{
			"gate default serve block",
			`gate {
				auth_base_url https://foo.com
				users {
					admin
				}
			}`,
			&GateServe{
				Config: &app.Config{
					Users: []app.User{
						{ID: "admin"},
					},
				},
				ServeConfig: app.ServeConfig{
					AuthBaseURL: "https://foo.com",
				},
			},
		},
		{
			"gate default serve keyword block",
			`gate serve {
				data_dir /foo/bar
			}`,
			&GateServe{
				ServeConfig: app.ServeConfig{
					DataDir: "/foo/bar",
				},
			},
		},
		{
			"gate serve with a zero shared value is still inline",
			`gate serve {
				data_dir /foo/bar
				cookie_ttl 0s
			}`,
			&GateServe{
				Config: &app.Config{},
				ServeConfig: app.ServeConfig{
					DataDir: "/foo/bar",
				},
			},
		},
		{
			"gate named serve block",
			`gate serve example.com {
				data_dir /foo/bar
				secret "` + cookieSecretB64 + `"
				auth_base_url https://foo.com
				sign_in_url https://auth.foo.com
				default_next https://admin.foo.com
				cookie_domain foo.com
				cookie_name_prefix foo
				cookie_path /foo
				cookie_ttl 30d
				invite_ttl 24h
				rp {
					id example.com
					display_name "Example"
					origin https://foo.com
					origin https://example.com
				}
				users {
					zaphod "Zaphod" admin crew
					trillian "Trillian" admin crew
					marvin
				}
			}`,
			&GateServe{
				Name: "example.com",
				Config: &app.Config{
					Secret:           cookieSecret,
					SignInURL:        "https://auth.foo.com",
					CookieDomain:     "foo.com",
					CookieNamePrefix: "foo",
					CookiePath:       "/foo",
					CookieTTL:        time.Hour * 24 * 30,
					Users: []app.User{
						{
							ID:   "zaphod",
							Name: "Zaphod",
							Tags: []string{"admin", "crew"},
						},
						{
							ID:   "trillian",
							Name: "Trillian",
							Tags: []string{"admin", "crew"},
						},
						{
							ID: "marvin",
						},
					},
				},
				ServeConfig: app.ServeConfig{
					DataDir:     "/foo/bar",
					AuthBaseURL: "https://foo.com",
					DefaultNext: "https://admin.foo.com",
					InviteTTL:   time.Hour * 24,
					RP: app.RelyingParty{
						ID:          "example.com",
						DisplayName: "Example",
						Origins: []string{
							"https://foo.com",
							"https://example.com",
						},
					},
				},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			actual, err := parseCaddyfile(caddyfile.NewTestDispenser(c.input))
			ensure.Nil(t, err)
			ensure.DeepEqual(t, actual, c.expected)
		})
	}
}

func TestErrorParseCaddyfile(t *testing.T) {
	cases := []struct{ name, input, err string }{
		{
			"gate foo",
			`gate foo`,
			`unexpected argument: "foo"`,
		},
		{
			"gate serve with missing name",
			`gate serve`,
			"key serve has no value",
		},
		{
			"gate invalid default serve option",
			`gate {
				foo bar
			}`,
			"unrecognized key: foo",
		},
		{
			"gate invalid default serve rp option",
			`gate {
				rp {
					foo bar
				}
			}`,
			"unrecognized key: foo",
		},
		{
			"gate invalid default serve ttl",
			`gate {
				cookie_ttl 1f
			}`,
			"unknown unit",
		},
		{
			"gate invalid default serve missing b64",
			`gate {
				secret
			}`,
			"key secret has no value",
		},
		{
			"gate invalid default serve b64",
			`gate {
				secret "$"
			}`,
			"illegal base64 data",
		},
		{
			"gate guard missing name",
			`gate guard`,
			"key guard has no value",
		},
		{
			"default gate with and no tags",
			`gate with`,
			"key with has no value",
		},
		{
			"named gate with with and no tags",
			`gate guard example.com with`,
			"key with has no value",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			actual, err := parseCaddyfile(caddyfile.NewTestDispenser(c.input))
			ensure.Nil(t, actual)
			ensure.StringContains(t, err.Error(), c.err)
		})
	}
}

func TestGateAppStartStop(t *testing.T) {
	ensure.Nil(t, (&Gate{}).Start())
	ensure.Nil(t, (&Gate{}).Stop())
}

func TestMissingAssociatedConfigDefault(t *testing.T) {
	g := GateGuard{gate: &Gate{}}
	ensure.Err(t, g.ServeHTTP(nil, nil, nil),
		regexp.MustCompile("default gate guard used without defining the default gate config"))
}

func TestMissingAssociatedConfigNamed(t *testing.T) {
	g := GateGuard{Name: "foo", gate: &Gate{}}
	ensure.Err(t, g.ServeHTTP(nil, nil, nil),
		regexp.MustCompile(`gate "foo" guard used without defining the gate "foo" config`))
}

func newValidApp(t testing.TB) *app.App {
	secret := make([]byte, 32)
	rand.Read(secret)
	a, err := app.NewApp(app.Config{
		Secret: secret,
		Users: []app.User{
			{ID: "zaphod", Tags: []string{"admin"}},
			{ID: "marvin"},
		},
	}, app.ServeConfig{
		DataDir: t.TempDir(),
		RP: app.RelyingParty{
			ID:          "foo.com",
			DisplayName: "Foo",
			Origins:     []string{"https://foo.com"},
		},
	})
	ensure.Nil(t, err)
	return a
}

func TestGateIsNotSignedIn(t *testing.T) {
	a := newValidApp(t)
	g := GateGuard{
		gate: &Gate{
			verifiers: map[string]*app.Verifier{
				"": a.Verifier(),
			},
		},
	}
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	ensure.Nil(t, g.ServeHTTP(w, r, nil))
	ensure.DeepEqual(t, w.Code, http.StatusSeeOther)
	ensure.StringContains(t, w.Header().Get("Location"), "https://foo.com?next=")
}

func TestGateIsNotSignedInNextURL(t *testing.T) {
	cases := []struct {
		name     string
		target   string
		expected string
	}{
		{
			name:     "origin form request",
			target:   "/secret/page?q=1",
			expected: "https://example.com/secret/page?q=1",
		},
		{
			// Absolute-form request targets (RFC 9112 §3.2.2) populate the
			// scheme and host on r.URL. They used to get the host prepended
			// again, sealing a next URL with a duplicated hostname.
			name:     "absolute form request",
			target:   "https://protected.example.com/secret/page?q=1",
			expected: "https://protected.example.com/secret/page?q=1",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			secret := make([]byte, 32)
			rand.Read(secret)
			a, err := app.NewApp(app.Config{
				Secret: secret,
				Users: []app.User{
					{ID: "neo"},
				},
			}, app.ServeConfig{
				DataDir: t.TempDir(),
				RP: app.RelyingParty{
					ID:          "example.com",
					DisplayName: "Example",
					Origins:     []string{"https://auth.example.com"},
				},
			})
			ensure.Nil(t, err)
			g := GateGuard{
				gate: &Gate{
					verifiers: map[string]*app.Verifier{
						"": a.Verifier(),
					},
				},
			}
			r := httptest.NewRequest("GET", c.target, nil)
			w := httptest.NewRecorder()
			ensure.Nil(t, g.ServeHTTP(w, r, nil))
			ensure.DeepEqual(t, w.Code, http.StatusSeeOther)
			loc, err := url.Parse(w.Header().Get("Location"))
			ensure.Nil(t, err)
			next, err := sookie.Open[string](
				guardNextSecret(t, secret), loc.Query().Get("next"))
			ensure.Nil(t, err)
			ensure.DeepEqual(t, next, c.expected)
		})
	}
}

// guardNextSecret mirrors the derivation of the app's next url secret.
func guardNextSecret(t testing.TB, secret []byte) []byte {
	t.Helper()
	next, err := hkdf.Expand(sha256.New, secret, "next", 32)
	ensure.Nil(t, err)
	return next
}

// newSignedInApp returns an app with a single user "neo", along with a valid
// auth cookie value for them. The app has no keys in its data dir, like a
// guard running on a different machine from the one users sign in on.
func newSignedInApp(t testing.TB) (*app.App, string) {
	t.Helper()
	secret := make([]byte, 32)
	rand.Read(secret)
	a, err := app.NewApp(app.Config{
		Secret: secret,
		Users: []app.User{
			{ID: "neo"},
		},
	}, app.ServeConfig{
		DataDir: t.TempDir(),
		RP: app.RelyingParty{
			ID:          "example.com",
			DisplayName: "Example",
			Origins:     []string{"https://auth.example.com"},
		},
	})
	ensure.Nil(t, err)
	authSecret, err := hkdf.Expand(sha256.New, secret, "authCookie", 32)
	ensure.Nil(t, err)
	auth, err := sookie.Seal(authSecret, time.Now().Add(time.Hour), "neo")
	ensure.Nil(t, err)
	return a, auth
}

func TestGateStripsGateCookies(t *testing.T) {
	a, auth := newSignedInApp(t)
	g := GateGuard{
		gate: &Gate{
			verifiers: map[string]*app.Verifier{
				"": a.Verifier(),
			},
		},
	}

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Add("Cookie", "foo=1; gate-a="+auth+"; gate-l=x")
	r.Header.Add("Cookie", "gate-r=y; bar=2")
	w := httptest.NewRecorder()
	var upstream *http.Request
	ensure.Nil(t, g.ServeHTTP(w, r, caddyhttp.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) error {
			upstream = r
			return nil
		})))
	ensure.NotNil(t, upstream)
	ensure.DeepEqual(t, upstream.Header.Values("Cookie"), []string{"foo=1; bar=2"})
}

func TestGateInvalidCookieRedirectsToSignIn(t *testing.T) {
	a := newValidApp(t)
	g := GateGuard{
		gate: &Gate{
			verifiers: map[string]*app.Verifier{
				"": a.Verifier(),
			},
		},
	}
	// sealed with a different secret, as happens after rotating it
	otherSecret := make([]byte, 32)
	rand.Read(otherSecret)
	stale, err := sookie.Seal(otherSecret, time.Now().Add(time.Hour), "zaphod")
	ensure.Nil(t, err)
	for _, value := range []string{stale, "garbage"} {
		r := httptest.NewRequest("GET", "/", nil)
		r.AddCookie(&http.Cookie{Name: "gate-a", Value: value})
		w := httptest.NewRecorder()
		ensure.Nil(t, g.ServeHTTP(w, r, nil))
		ensure.DeepEqual(t, w.Code, http.StatusSeeOther)
		ensure.StringContains(t, w.Header().Get("Set-Cookie"), "gate-a=;")
	}
}

// The guard must accept a session without having the user's passkeys in its
// own keys.json, since it may run on a different machine than sign-in.
func TestGateSignedInWithoutLocalKeys(t *testing.T) {
	a, auth := newSignedInApp(t)
	g := GateGuard{
		HeaderUserID: true,
		gate: &Gate{
			verifiers: map[string]*app.Verifier{
				"": a.Verifier(),
			},
		},
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "gate-a", Value: auth})
	w := httptest.NewRecorder()
	var upstream *http.Request
	ensure.Nil(t, g.ServeHTTP(w, r, caddyhttp.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) error {
			upstream = r
			return nil
		})))
	ensure.NotNil(t, upstream)
	ensure.DeepEqual(t, upstream.Header.Get("X-Caddy-Gate-User-ID"), "neo")
}

func TestGateStripsSpoofedIdentityHeaders(t *testing.T) {
	a, auth := newSignedInApp(t)
	for _, enabled := range []bool{false, true} {
		g := GateGuard{
			HeaderUserID:   enabled,
			HeaderUserTags: enabled,
			gate: &Gate{
				verifiers: map[string]*app.Verifier{
					"": a.Verifier(),
				},
			},
		}
		r := httptest.NewRequest("GET", "/", nil)
		r.AddCookie(&http.Cookie{Name: "gate-a", Value: auth})
		r.Header["X-Caddy-Gate-User-Id"] = []string{"zaphod"}
		r.Header["X-Caddy-Gate-User_ID"] = []string{"zaphod"}
		r.Header["x_caddy_gate_user_tags"] = []string{"admin"}
		var upstream *http.Request
		ensure.Nil(t, g.ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) error {
				upstream = r
				return nil
			})))
		ensure.NotNil(t, upstream)
		var expected http.Header
		if enabled {
			expected = http.Header{"X-Caddy-Gate-User-Id": {"neo"}}
		}
		for k, v := range upstream.Header {
			if strings.Contains(strings.ToLower(k), "gate") {
				ensure.DeepEqual(t, v, expected[k])
			}
		}
		if enabled {
			ensure.DeepEqual(t, upstream.Header.Get("X-Caddy-Gate-User-ID"), "neo")
		}
	}
}

func newSecretB64(t testing.TB) ([]byte, string) {
	t.Helper()
	secret := make([]byte, 32)
	rand.Read(secret)
	return secret, base64.RawURLEncoding.EncodeToString(secret)
}

func TestParseGlobalOption(t *testing.T) {
	secret, secretB64 := newSecretB64(t)
	var existing any
	for _, input := range []string{
		`gate {
			secret "` + secretB64 + `"
			cookie_domain example.com
			sign_in_url https://auth.example.com
			users {
				neo "Neo" admin
			}
		}`,
		`gate other.com {
			secret "` + secretB64 + `"
			cookie_domain other.com
			sign_in_url https://auth.other.com
			users {
				trinity
			}
		}`,
	} {
		var err error
		existing, err = parseGlobalOption(caddyfile.NewTestDispenser(input), existing)
		ensure.Nil(t, err)
	}
	gateApp, ok := existing.(httpcaddyfile.App)
	ensure.True(t, ok)
	ensure.DeepEqual(t, gateApp.Name, "gate")
	var gate Gate
	ensure.Nil(t, json.Unmarshal(gateApp.Value, &gate))
	ensure.DeepEqual(t, gate.Configs, map[string]app.Config{
		"": {
			Secret:       secret,
			CookieDomain: "example.com",
			SignInURL:    "https://auth.example.com",
			Users:        app.Users{{ID: "neo", Name: "Neo", Tags: []string{"admin"}}},
		},
		"other.com": {
			Secret:       secret,
			CookieDomain: "other.com",
			SignInURL:    "https://auth.other.com",
			Users:        app.Users{{ID: "trinity"}},
		},
	})
}

func TestParseGlobalOptionErrors(t *testing.T) {
	cases := []struct{ name, input, err string }{
		{
			"serve only option",
			`gate {
				data_dir /foo
			}`,
			"unrecognized key: data_dir",
		},
		{
			"relying party",
			`gate {
				rp {
					id example.com
				}
			}`,
			"unrecognized key: rp",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseGlobalOption(caddyfile.NewTestDispenser(c.input), nil)
			ensure.StringContains(t, err.Error(), c.err)
		})
	}
}

func TestParseGlobalOptionRedefined(t *testing.T) {
	existing, err := parseGlobalOption(caddyfile.NewTestDispenser(`gate { cookie_domain a.com }`), nil)
	ensure.Nil(t, err)
	_, err = parseGlobalOption(caddyfile.NewTestDispenser(`gate { cookie_domain b.com }`), existing)
	ensure.StringContains(t, err.Error(), "default gate config redefined")
}

func newGlobalConfig(t testing.TB) app.Config {
	t.Helper()
	secret, _ := newSecretB64(t)
	return app.Config{
		Secret:       secret,
		CookieDomain: "example.com",
		SignInURL:    "https://auth.example.com",
		Users:        app.Users{{ID: "neo", Tags: []string{"admin"}}},
	}
}

func newProvisionedGate(t testing.TB, configs map[string]app.Config) *Gate {
	t.Helper()
	g := &Gate{Configs: configs}
	ensure.Nil(t, g.Provision(caddy.Context{}))
	return g
}

func TestGateProvisionInvalidConfig(t *testing.T) {
	c := newGlobalConfig(t)
	c.SignInURL = ""
	g := &Gate{Configs: map[string]app.Config{"example.com": c}}
	ensure.Err(t, g.Provision(caddy.Context{}),
		regexp.MustCompile(`gate "example.com": .*must specify sign_in_url`))
}

func TestServeWithGlobalConfig(t *testing.T) {
	gate := newProvisionedGate(t, map[string]app.Config{"": newGlobalConfig(t)})
	s := GateServe{ServeConfig: app.ServeConfig{DataDir: t.TempDir()}}
	ensure.Nil(t, s.provision(gate))
	ensure.True(t, gate.served[""])
	ensure.True(t, gate.verifiers[""] == s.app.Verifier())
}

func TestServeWithInlineConfig(t *testing.T) {
	gate := newProvisionedGate(t, nil)
	c := newGlobalConfig(t)
	c.CookieDomain, c.SignInURL = "", ""
	s := GateServe{
		Config: &c,
		ServeConfig: app.ServeConfig{
			DataDir: t.TempDir(),
			RP: app.RelyingParty{
				ID:      "example.com",
				Origins: []string{"https://auth.example.com"},
			},
		},
	}
	ensure.Nil(t, s.provision(gate))
	ensure.Nil(t, gate.Start())
	v := gate.verifiers[""]
	ensure.True(t, v == s.app.Verifier())
	// the shared config defaults from the relying party
	ensure.DeepEqual(t, v.SignInURL(), "https://auth.example.com")
}

func TestServeProvisionErrors(t *testing.T) {
	gate := newProvisionedGate(t, map[string]app.Config{"": newGlobalConfig(t)})

	both := GateServe{
		Config:      new(newGlobalConfig(t)),
		ServeConfig: app.ServeConfig{DataDir: t.TempDir()},
	}
	ensure.Err(t, both.provision(gate),
		regexp.MustCompile("default gate config defined both globally and inline"))

	neither := GateServe{Name: "foo", ServeConfig: app.ServeConfig{DataDir: t.TempDir()}}
	ensure.Err(t, neither.provision(gate),
		regexp.MustCompile(`gate "foo" serve used without defining the gate "foo" config`))

	first := GateServe{ServeConfig: app.ServeConfig{DataDir: t.TempDir()}}
	ensure.Nil(t, first.provision(gate))
	again := GateServe{ServeConfig: app.ServeConfig{DataDir: t.TempDir()}}
	ensure.Err(t, again.provision(gate), regexp.MustCompile("default gate serve redefined"))
}

// A guard only needs the global config, so it works on a machine that
// doesn't serve sign-in.
func TestGuardWithGlobalConfigOnly(t *testing.T) {
	c := newGlobalConfig(t)
	gate := newProvisionedGate(t, map[string]app.Config{"": c})
	g := GateGuard{gate: gate}
	gate.guarded = append(gate.guarded, g.Name)
	ensure.Nil(t, gate.Start())

	authSecret, err := hkdf.Expand(sha256.New, c.Secret, "authCookie", 32)
	ensure.Nil(t, err)
	auth, err := sookie.Seal(authSecret, time.Now().Add(time.Hour), "neo")
	ensure.Nil(t, err)
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "gate-a", Value: auth})
	var upstream *http.Request
	ensure.Nil(t, g.ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) error {
			upstream = r
			return nil
		})))
	ensure.NotNil(t, upstream)

	r = httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	ensure.Nil(t, g.ServeHTTP(w, r, nil))
	ensure.DeepEqual(t, w.Code, http.StatusSeeOther)
	ensure.StringContains(t, w.Header().Get("Location"), "https://auth.example.com?next=")
}

func TestGateStartGuardWithoutConfig(t *testing.T) {
	gate := newProvisionedGate(t, map[string]app.Config{"": newGlobalConfig(t)})
	gate.guarded = []string{"", "foo"}
	ensure.Err(t, gate.Start(),
		regexp.MustCompile(`gate "foo" guard used without defining the gate "foo" config`))
}

func TestAdaptCaddyfile(t *testing.T) {
	_, secretB64 := newSecretB64(t)
	input := `{
		gate {
			secret "` + secretB64 + `"
			cookie_domain example.com
			sign_in_url https://auth.example.com
			users {
				neo
			}
		}
	}

	http://auth.example.com {
		gate serve {
			data_dir ` + t.TempDir() + `
		}
	}

	http://admin.example.com {
		gate with admin
	}`
	adapter := caddyfile.Adapter{ServerType: httpcaddyfile.ServerType{}}
	cfgJSON, _, err := adapter.Adapt([]byte(input), nil)
	ensure.Nil(t, err)
	var cfg struct {
		Apps struct {
			Gate Gate `json:"gate"`
		} `json:"apps"`
	}
	ensure.Nil(t, json.Unmarshal(cfgJSON, &cfg))
	ensure.DeepEqual(t, cfg.Apps.Gate.Configs[""].CookieDomain, "example.com")
	ensure.Nil(t, caddy.Validate(mustConfig(t, cfgJSON)))
}

func mustConfig(t testing.TB, cfgJSON []byte) *caddy.Config {
	t.Helper()
	var cfg caddy.Config
	ensure.Nil(t, json.Unmarshal(cfgJSON, &cfg))
	return &cfg
}
