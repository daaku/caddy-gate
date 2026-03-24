package app

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
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

type Config struct {
	Secret []byte
}

// User implements webauthn.User.
type User struct {
	ID          string
	DisplayName string
	Tags        []string
	Credentials []webauthn.Credential
}

func (u User) WebAuthnID() []byte                         { return []byte(u.ID) }
func (u User) WebAuthnName() string                       { return u.DisplayName }
func (u User) WebAuthnDisplayName() string                { return u.DisplayName }
func (u User) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

type Store struct {
	Path  string
	Lock  sync.Mutex
	Users atomic.Pointer[map[string]User]
}

func (s *Store) Save(userID string, credential *webauthn.Credential) error {
	s.Lock.Lock()
	defer s.Lock.Unlock()
	// TODO: write to file
	for {
		e := s.Users.Load()
		eNew := make(map[string]User, len(*e))
		for k, v := range *e {
			if k == userID {
				v.Credentials = append(v.Credentials, *credential)
			}
			eNew[k] = v
		}
		if s.Users.CompareAndSwap(e, &eNew) {
			break
		}
	}
	return nil
}

func (s *Store) ByID(userID string) (User, bool) {
	user, found := (*s.Users.Load())[userID]
	return user, found
}

type invite struct {
	UserID    string
	ExpiresAt time.Time
}

func (i *invite) expired() bool {
	return i.ExpiresAt.After(time.Now())
}

func mapSet[T any](m *atomic.Pointer[map[string]T], k string, v T) {
	for {
		e := m.Load()
		eNew := make(map[string]T, len(*e))
		for k, v := range *e {
			eNew[k] = v
		}
		eNew[k] = v
		if m.CompareAndSwap(e, &eNew) {
			return
		}
	}
}

type App struct {
	Config   Config
	WebAuthN *webauthn.WebAuthn
	invites  atomic.Pointer[map[string]invite]
	Users    Store
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

func (a *App) inviteUser(r *http.Request) (User, error) {
	invite, found := (*a.invites.Load())[r.PathValue("invite")]
	if !found || invite.expired() {
		return User{}, httpError(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			a.pageError(w, r, g.Text("No valid invite found.")).Render(w)
		})
	}
	user, found := a.Users.ByID(invite.UserID)
	if !found {
		return User{}, serr.Errorf("invalid user id in invite: %s", invite.UserID)
	}
	return user, nil
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

	if err := a.Users.Save(user.ID, credential); err != nil {
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
