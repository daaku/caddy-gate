package caddygate

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/daaku/caddy-gate/internal/app"
	"github.com/daaku/ensure"
)

func h(v string) httpcaddyfile.Helper {
	return httpcaddyfile.Helper{}.WithDispenser(caddyfile.NewTestDispenser(v))
}

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
			actual, err := parseCaddyfile(h(c.input))
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
			"unable to identify serve or guard",
		},
		{
			"gate serve with missing name",
			`gate serve`,
			"must specify name",
		},
		{
			"gate invalid default serve option",
			`gate {
				foo bar
			}`,
			"unexpected option in serve block",
		},
		{
			"gate invalid default serve rp option",
			`gate {
				rp {
					foo bar
				}
			}`,
			"unexpected option in rp block",
		},
		{
			"gate invalid default missing origin value",
			`gate {
				rp {
					origin
				}
			}`,
			"wrong argument count",
		},
		{
			"gate invalid default serve missing ttl",
			`gate {
				cookie_ttl
			}`,
			"wrong argument count",
		},
		{
			"gate invalid default serve ttl",
			`gate {
				cookie_ttl 1f
			}`,
			"invalid duration string",
		},
		{
			"gate invalid default serve missing b64",
			`gate {
				secret
			}`,
			"wrong argument count",
		},
		{
			"gate invalid default serve b64",
			`gate {
				secret "$"
			}`,
			"invalid base64 URL encoded string",
		},
		{
			"gate invalid default serve missing string",
			`gate {
				cookie_path
			}`,
			"wrong argument count",
		},
		{
			"gate guard missing name",
			`gate guard`,
			"must specify name",
		},
		{
			"default gate with and no tags",
			`gate with`,
			"must specify tags",
		},
		{
			"named gate with with and no tags",
			`gate guard example.com with`,
			"must specify tags",
		},
		{
			"gate guard with missing name",
			`gate guard`,
			"must specify name",
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

func TestGateAppStartStop(t *testing.T) {
	ensure.Nil(t, (&Gate{}).Start())
	ensure.Nil(t, (&Gate{}).Stop())
}

func TestMissingAssociatedConfigDefault(t *testing.T) {
	g := GateGuard{g: &Gate{}}
	ensure.Err(t, g.ServeHTTP(nil, nil, nil),
		regexp.MustCompile("default gate guard used without defining associated default serve"))
}

func TestMissingAssociatedConfigNamed(t *testing.T) {
	g := GateGuard{Name: "foo", g: &Gate{}}
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
			{ID: "admin"},
		},
	})
	ensure.Nil(t, err)
	return a
}

func TestGateIsNotSignedIn(t *testing.T) {
	a := newValidApp(t)
	g := GateGuard{
		g: &Gate{
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
