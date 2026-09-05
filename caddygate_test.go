package caddygate

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
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
				Config: app.Config{
					AuthBaseURL: "https://foo.com",
					Users: []app.User{
						{ID: "admin"},
					},
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
				Config: app.Config{
					DataDir:          "/foo/bar",
					Secret:           cookieSecret,
					AuthBaseURL:      "https://foo.com",
					SignInURL:        "https://auth.foo.com",
					DefaultNext:      "https://admin.foo.com",
					CookieDomain:     "foo.com",
					CookieNamePrefix: "foo",
					CookiePath:       "/foo",
					CookieTTL:        time.Hour * 24 * 30,
					InviteTTL:        time.Hour * 24,
					RP: app.RelyingParty{
						ID:          "example.com",
						DisplayName: "Example",
						Origins: []string{
							"https://foo.com",
							"https://example.com",
						},
					},
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
		regexp.MustCompile("default gate guard used without defining associated default serve"))
}

func TestMissingAssociatedConfigNamed(t *testing.T) {
	g := GateGuard{Name: "foo", gate: &Gate{}}
	ensure.Err(t, g.ServeHTTP(nil, nil, nil),
		regexp.MustCompile(`named gate guard "foo" used without defining associated named serve`))
}

func newValidApp(t testing.TB) *app.App {
	secret := make([]byte, 32)
	rand.Read(secret)
	a, err := app.NewApp(app.Config{
		DataDir: t.TempDir(),
		Secret:  secret,
		RP: app.RelyingParty{
			ID:          "foo.com",
			DisplayName: "Foo",
			Origins:     []string{"https://foo.com"},
		},
		Users: []app.User{
			{ID: "zaphod", Tags: []string{"admin"}},
			{ID: "marvin"},
		},
	})
	ensure.Nil(t, err)
	return a
}

func TestGateIsNotSignedIn(t *testing.T) {
	a := newValidApp(t)
	g := GateGuard{
		gate: &Gate{
			app: map[string]*app.App{
				"": a,
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
				DataDir: t.TempDir(),
				Secret:  secret,
				RP: app.RelyingParty{
					ID:          "example.com",
					DisplayName: "Example",
					Origins:     []string{"https://auth.example.com"},
				},
				Users: []app.User{
					{ID: "neo"},
				},
			})
			ensure.Nil(t, err)
			g := GateGuard{
				gate: &Gate{
					app: map[string]*app.App{
						"": a,
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
