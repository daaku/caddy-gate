// Package caddygate provides Passkey based authentication.
// It is meant for small use cases where you want to protect resources without
// depending on external auth services.
package caddygate

import (
	"path/filepath"
	"time"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(&Gate{})
}

// named instances (support multiple)
// config:
//   rpID
//   origin
//   cookie ttl
//   cookie secret (generated)
//   token secret (generated)
//   users (managed)
// user:
//   id
//   key
//   tags

type User struct{}

type FileStore struct {
	Path string
}

func (f *FileStore) Load(ctx caddy.Context) ([]User, error) {
	panic("unimplemented")
}

type Gate struct {
	Name         string        `json:"name,omitempty"`
	RPID         string        `json:"rpID,omitempty"`
	Origin       []string      `json:"origin,omitempty"`
	CookieTTL    time.Duration `json:"cookieTTL,omitempty"`
	CookieSecret []byte        `json:"cookieSecret,omitempty"`
	FileStore    string        `json:"fileStore,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (*Gate) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "com.github.daaku.caddygate",
		New: func() caddy.Module { return new(Gate) },
	}
}

func (g *Gate) name() string {
	if g.Name == "" {
		return "caddygate"
	}
	return g.Name
}

func (g *Gate) cookieTTL() time.Duration {
	if g.CookieTTL == 0 {
		return time.Hour * 24 * 30
	}
	return g.CookieTTL
}

func (g *Gate) fileStore() string {
	if g.FileStore == "" {
		return filepath.Join()
	}
	return g.FileStore
}

func (g *Gate) Provision(ctx caddy.Context) error {
	return nil
}
