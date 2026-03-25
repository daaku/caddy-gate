// Package app provides the caddygate application to register & authorize via
// passkeys.
package app

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daaku/serr"
	"github.com/daaku/sookie"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	atomicfile "github.com/natefinch/atomic"
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
	UsersFile        string
	CookieSecret     []byte
	CookieDomain     string
	CookiePath       string
	CookieNamePrefix string
	AuthCookieTTL    time.Duration
}

// User implements webauthn.User.
type User struct {
	ID          string                `json:"id"`
	DisplayName string                `json:"displayName"`
	Tags        []string              `json:"tags"`
	Credentials []webauthn.Credential `json:"credentials"`
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

	e := *s.Users.Load()
	eNew := make(map[string]User, len(e))
	maps.Copy(eNew, e)
	u := eNew[userID]
	u.Credentials = append(u.Credentials, *credential)
	eNew[userID] = u

	jsonB, err := json.MarshalIndent(eNew, "", "  ")
	if err != nil {
		return serr.Wrap(err)
	}

	if err := atomicfile.WriteFile(s.Path, bytes.NewReader(jsonB)); err != nil {
		return serr.Wrap(err)
	}
	s.Users.Store(&eNew)
	return nil
}

var ErrUserNotFound = errors.New("user not found")

func (s *Store) ByID(userID string) (User, error) {
	user, found := (*s.Users.Load())[userID]
	if !found {
		return User{}, serr.Wrap(ErrUserNotFound)
	}
	return user, nil
}

func NewStore(filename string) (*Store, error) {
	jsonB, err := os.ReadFile(filename)
	if err != nil {
		return nil, serr.Wrap(err)
	}
	users := map[string]User{}
	if err := json.Unmarshal(jsonB, &users); err != nil {
		return nil, serr.Wrap(err)
	}
	s := Store{Path: filename}
	s.Users.Store(&users)
	return &s, nil
}

type invite struct {
	UserID    string
	ExpiresAt time.Time
}

func (i *invite) expired() bool {
	return i.ExpiresAt.After(time.Now())
}

func mutateMap[T any](m *atomic.Pointer[map[string]T], f func(map[string]T)) {
	for {
		e := m.Load()
		eNew := make(map[string]T, len(*e))
		maps.Copy(eNew, *e)
		f(eNew)
		if m.CompareAndSwap(e, &eNew) {
			return
		}
	}
}

type App struct {
	Config   Config
	WebAuthN *webauthn.WebAuthn
	Users    *Store

	invites            atomic.Pointer[map[string]invite]
	registerCookieName string
	loginCookieName    string
	authCookieName     string
	handler            http.HandlerFunc
}

func NewApp(c Config, webauthn *webauthn.WebAuthn) (*App, error) {
	if c.CookiePath == "" {
		c.CookiePath = "/"
	}
	if c.CookieDomain == "" {
		c.CookieDomain = webauthn.Config.GetRPID()
	}
	if c.AuthCookieTTL == 0 {
		c.AuthCookieTTL = time.Hour * 24 * 30
	}
	if c.CookieNamePrefix == "" {
		c.CookieNamePrefix = "gate-"
	}
	if c.UsersFile == "" {
		return nil, serr.Errorf("must specify UsersFile in config")
	}
	store, err := NewStore(c.UsersFile)
	if err != nil {
		return nil, err
	}
	a := &App{
		Config:             c,
		WebAuthN:           webauthn,
		Users:              store,
		registerCookieName: c.CookieNamePrefix + "r",
		loginCookieName:    c.CookieNamePrefix + "l",
		authCookieName:     c.CookieNamePrefix + "a",
	}
	a.invites.Store(&map[string]invite{})
	m := http.NewCrossOriginProtection().Handler(a.mux())
	a.handler = m.ServeHTTP
	return a, nil
}

func (a *App) registerCookie() http.Cookie {
	return http.Cookie{
		Name:     a.registerCookieName,
		Path:     a.Config.CookiePath,
		Domain:   a.Config.CookieDomain,
		MaxAge:   maxAge(time.Minute * 10),
		Secure:   true,
		HttpOnly: true,
	}
}

func (a *App) loginCookie() http.Cookie {
	return http.Cookie{
		Name:     a.loginCookieName,
		Path:     a.Config.CookiePath,
		Domain:   a.Config.CookieDomain,
		MaxAge:   maxAge(time.Minute * 10),
		Secure:   true,
		HttpOnly: true,
	}
}

func (a *App) authCookie() http.Cookie {
	return http.Cookie{
		Name:     a.authCookieName,
		Path:     a.Config.CookiePath,
		Domain:   a.Config.CookieDomain,
		MaxAge:   maxAge(a.Config.AuthCookieTTL),
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

// returns the current logged in user
func (a *App) currentUser(r *http.Request) (User, error) {
	userID, err := sookie.Get[string](a.Config.CookieSecret, r, a.authCookieName)
	if err != nil {
		return User{}, serr.Wrap(err)
	}
	return a.Users.ByID(userID)
}

// returns the user from the invite
func (a *App) inviteUser(r *http.Request) (string, User, error) {
	inviteID := r.PathValue("invite")
	invite, found := (*a.invites.Load())[inviteID]
	if !found || invite.expired() {
		return "", User{}, httpError(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			a.pageError(g.Text("No valid invite found.")).Render(w)
		})
	}
	user, err := a.Users.ByID(invite.UserID)
	if err != nil {
		return "", User{}, err
	}
	return inviteID, user, nil
}

func (a *App) inviteGet(w http.ResponseWriter, r *http.Request) error {
	user, err := a.currentUser(r)
	if err != nil {
		return err
	}

	if !slices.Contains(user.Tags, "admin") {
		return serr.Errorf("only admins can create invites")
	}

	// TODO render create invite ui

	return nil
}

func (a *App) invitePost(w http.ResponseWriter, r *http.Request) error {
	user, err := a.currentUser(r)
	if err != nil {
		return err
	}

	if !slices.Contains(user.Tags, "admin") {
		return serr.Errorf("only admins can create invites")
	}

	// TODO render qr code and share invite ui

	return nil
}

func (a *App) registerGet(w http.ResponseWriter, r *http.Request) error {
	_, user, err := a.inviteUser(r)
	if err != nil {
		return err
	}

	options, sessionData, err := a.WebAuthN.BeginRegistration(user,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred),
	)
	if err != nil {
		return serr.Wrap(err)
	}

	sookie.Set(a.Config.CookieSecret, w, sessionData, a.registerCookie())
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
	return nil
}

const inputCredential = "credential"

func (a *App) registerPost(w http.ResponseWriter, r *http.Request) error {
	inviteID, user, err := a.inviteUser(r)
	if err != nil {
		return err
	}

	sessionData, err := sookie.Get[webauthn.SessionData](
		a.Config.CookieSecret, r, a.registerCookieName)
	if err != nil {
		return serr.Wrap(err)
	}

	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(
		strings.NewReader(r.FormValue(inputCredential)),
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

	mutateMap(&a.invites, func(m map[string]invite) {
		delete(m, inviteID)
	})

	if err := sookie.Set(a.Config.CookieSecret, w, user.ID, a.authCookie()); err != nil {
		return serr.Wrap(err)
	}

	// TODO redirect somewhere?

	return nil
}

func (a *App) loginGet(w http.ResponseWriter, r *http.Request) error {
	credentialAssertion, sessionData, err := a.WebAuthN.BeginDiscoverableLogin()
	if err != nil {
		return serr.Wrap(err)
	}
	if err := sookie.Set(a.Config.CookieSecret, w, sessionData, a.loginCookie()); err != nil {
		return serr.Wrap(err)
	}
	// TODO render login page
	json.NewEncoder(w).Encode(credentialAssertion)
	return nil
}

func (a *App) loginPost(w http.ResponseWriter, r *http.Request) error {
	sessionData, err := sookie.Get[*webauthn.SessionData](
		a.Config.CookieSecret, r, a.loginCookieName)
	if err != nil {
		return serr.Wrap(err)
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(r.Body)
	if err != nil {
		return serr.Wrap(err)
	}

	credential, err := a.WebAuthN.ValidateDiscoverableLogin(a.discoverUser, *sessionData, parsedResponse)
	if err != nil {
		return serr.Wrap(err)
	}

	log.Printf("%+v\n", credential)

	// TODO: what user do we have?

	return nil
}

func (a *App) discoverUser(rawID, userHandle []byte) (webauthn.User, error) {
	log.Printf("discoverUser: %s %s", rawID, userHandle)
	return nil, nil
}

func (a *App) logoutPost(w http.ResponseWriter, r *http.Request) error {
	sookie.Del(w, r, a.authCookie())
	return nil
}

func (a *App) mux() *http.ServeMux {
	var m http.ServeMux
	m.Handle("GET /invite", a.wrap(a.inviteGet))
	m.Handle("POST /invite", a.wrap(a.invitePost))
	m.Handle("GET /register/{invite}", a.wrap(a.registerGet))
	m.Handle("POST /register/{invite}", a.wrap(a.registerPost))
	m.Handle("GET /login", a.wrap(a.loginGet))
	m.Handle("POST /login", a.wrap(a.loginPost))
	m.Handle("POST /logout", a.wrap(a.logoutPost))
	return &m
}

func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
}

//go:embed app.js
var appJS string

//go:embed app.css
var appCSS string

func (a *App) pageShell(title string, body g.Node) g.Node {
	return h.Doctype(
		h.HTML(h.Lang("en"),
			h.Head(h.Meta(h.Charset("utf-8")),
				h.Meta(h.Name("viewport"), h.Content("width=device-width, initial-scale=1")),
				h.TitleEl(g.Text(title)),
				h.Style(appCSS),
				h.Script(g.Raw(appJS))),
			body))
}

func (a *App) pageStd(title string, body g.Node) g.Node {
	return a.pageShell(title,
		h.Body(h.Main(h.Class("container"), body)))
}

func (a *App) pageError(body g.Node) g.Node {
	return a.pageStd("Error", body)
}
