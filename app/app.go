package app

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/daaku/serr"
	"github.com/daaku/sookie"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	g "maragu.dev/gomponents"
	h "maragu.dev/gomponents/html"
)

type httpError http.HandlerFunc

func (he httpError) Error() string {
	return "user error"
}

func maxAge(d time.Duration) int {
	return int(d.Seconds())
}

// webauthnUser implements webauthn.User
type webauthnUser struct {
	id          []byte
	name        string
	displayName string
	credentials []webauthn.Credential
}

func (u *webauthnUser) WebAuthnID() []byte                         { return u.id }
func (u *webauthnUser) WebAuthnName() string                       { return u.name }
func (u *webauthnUser) WebAuthnDisplayName() string                { return u.displayName }
func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

type Config struct {
	Secret []byte
}

type Store interface {
	Save(context.Context, *webauthn.Credential) error
}

type invite struct {
	User      webauthnUser
	ExpiresAt time.Time
}

func (i *invite) expired() bool {
	return i.ExpiresAt.After(time.Now())
}

type App struct {
	Config   Config
	WebAuthN *webauthn.WebAuthn
	Invites  map[string]invite
	Store    Store
}

func (a *App) registerCookie() http.Cookie {
	return http.Cookie{
		Name:     "r",
		Path:     "/",
		Domain:   "daaku.org",
		MaxAge:   maxAge(time.Minute * 10),
		Secure:   true,
		HttpOnly: true,
	}
}

func (a *App) userCookie() http.Cookie {
	return http.Cookie{
		Name:     "u",
		Path:     "/",
		Domain:   "daaku.org",
		MaxAge:   maxAge(time.Hour * 24 * 30),
		Secure:   true,
		HttpOnly: true,
	}
}

func (a *App) wrap(f func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := f(w, r); err != nil {
			if he, ok := errors.AsType[httpError](err); ok {
				he(w, r)
			} else {
				fmt.Fprintf(os.Stderr, "%+v", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}
	}
}

func (a *App) createInvite(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (a *App) inviteUser(r *http.Request) (webauthn.User, error) {
	invite, found := a.Invites[r.PathValue("invite")]
	if !found {
		return nil, httpError(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			a.pageError(w, r, g.Text("No valid invite found.")).Render(w)
		})
	}
	if invite.expired() {
		// TODO
	}
	return &invite.User, nil
}

func (a *App) registerBegin(w http.ResponseWriter, r *http.Request) error {
	user, err := a.inviteUser(r)
	if err != nil {
		return err
	}

	options, sessionData, err := a.WebAuthN.BeginRegistration(user,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred),
	)
	if err != nil {
		return serr.Wrap(err)
	}

	sookie.Set(a.Config.Secret, w, sessionData, a.registerCookie())
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
	return nil
}

const kCredential = "credential"

func (a *App) registerFinish(w http.ResponseWriter, r *http.Request) error {
	user, err := a.inviteUser(r)
	if err != nil {
		return err
	}

	sessionData, err := sookie.Get[webauthn.SessionData](
		a.Config.Secret, r, a.registerCookie().Name)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			// TODO
		}
		if errors.Is(err, sookie.ErrExpired) {
			// TODO
		}
		return serr.Wrap(err)
	}

	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(
		strings.NewReader(r.FormValue(kCredential)),
	)
	if err != nil {
		return serr.Wrap(err)
	}

	credential, err := a.WebAuthN.CreateCredential(
		user, sessionData, parsedResponse)
	if err != nil {
		return serr.Wrap(err)
	}

	if err := a.Store.Save(r.Context(), credential); err != nil {
		return err
	}

	return nil
}

func (a *App) loginBegin(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (a *App) loginFinish(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (a *App) logout(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (a *App) mux() *http.ServeMux {
	var m http.ServeMux
	m.Handle("GET register", a.wrap(a.registerBegin))
	m.Handle("POST register", a.wrap(a.registerFinish))
	m.Handle("GET login", a.wrap(a.loginBegin))
	m.Handle("POST login", a.wrap(a.loginFinish))
	m.Handle("POST logout", a.wrap(a.logout))
	return &m
}

func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
}

//go:embed main.js
var mainJS string

//go:embed main.css
var mainCSS string

func (a *App) pageShell(title string, body g.Node) g.Node {
	return h.Doctype(
		h.HTML(h.Lang("en"),
			h.Head(h.Meta(h.Charset("utf-8")),
				h.Meta(h.Name("viewport"), h.Content("width=device-width, initial-scale=1")),
				h.TitleEl(g.Text(title)),
				h.Style(mainCSS),
				h.Script(g.Raw(mainJS))),
			body))
}

func (a *App) pageStd(w http.ResponseWriter, r *http.Request, title string, body g.Node) g.Node {
	return a.pageShell(title,
		h.Body(h.Main(h.Class("container"), body)))
}

func (a *App) pageError(w http.ResponseWriter, r *http.Request, body g.Node) g.Node {
	return a.pageStd(w, r, "Error", body)
}
