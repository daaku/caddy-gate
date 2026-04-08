package caddygate

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/daaku/caddygate/app"
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
				auth_base_url https://foo.com
				cookie_domain foo.com
				cookie_name_prefix foo
				cookie_path /foo
				cookie_secret "` + cookieSecretB64 + `"
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
					AuthBaseURL:      "https://foo.com",
					CookieDomain:     "foo.com",
					CookieNamePrefix: "foo",
					CookiePath:       "/foo",
					CookieTTL:        time.Hour * 24 * 30,
					CookieSecret:     cookieSecret,
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
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			actual, err := parseCaddyfile(h(c.input))
			ensure.Nil(t, actual)
			ensure.StringContains(t, err.Error(), c.err)
		})
	}
}
