// Package app provides the caddygate application to register & authorize via
// passkeys.
package app

import (
	"bytes"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/daaku/serr"
	"github.com/daaku/sookie"
	"github.com/davecgh/go-spew/spew"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	atomicfile "github.com/natefinch/atomic"
	g "maragu.dev/gomponents"
	h "maragu.dev/gomponents/html"
)

var dump = spew.Dump

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

var ErrUserNotFound = errors.New("user not found")

type userStore struct {
	path  string
	lock  sync.RWMutex
	users []User
}

func (s *userStore) internalByID(userID string) (*User, error) {
	i := slices.IndexFunc(s.users, func(u User) bool {
		return u.ID == userID
	})
	if i == -1 {
		return nil, serr.Wrap(ErrUserNotFound)
	}
	return &s.users[i], nil
}

func (s *userStore) RegisterCredential(userID string, credential *webauthn.Credential) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	u, err := s.internalByID(userID)
	if err != nil {
		return err
	}
	u.Credentials = append(u.Credentials, *credential)

	jsonB, err := json.MarshalIndent(s.users, "", "  ")
	if err != nil {
		return serr.Wrap(err)
	}

	if err := atomicfile.WriteFile(s.path, bytes.NewReader(jsonB)); err != nil {
		return serr.Wrap(err)
	}
	return nil
}

func (s *userStore) ByID(userID string) (*User, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.internalByID(userID)
}

func (s *userStore) FirstAdmin() *User {
	s.lock.RLock()
	defer s.lock.RUnlock()
	i := slices.IndexFunc(s.users, func(u User) bool {
		return slices.Contains(u.Tags, tagAdmin)
	})
	if i == -1 {
		return nil
	}
	return &s.users[i]
}

const tagAdmin = "admin"

func (s *userStore) Validate() error {
	s.lock.RLock()
	defer s.lock.RUnlock()

	if len(s.users) == 0 {
		return serr.Errorf("at least one user must be defined in %q", s.path)
	}

	validAdmins := slices.ContainsFunc(s.users, func(u User) bool {
		return slices.Contains(u.Tags, tagAdmin) && len(u.Credentials) > 0
	})
	if !validAdmins {
		return serr.Errorf("no admin user with credentials in %q", s.path)
	}

	return nil
}

func (s *userStore) Reload() error {
	s.lock.Lock()
	defer s.lock.Unlock()
	jsonB, err := os.ReadFile(s.path)
	if err != nil {
		return serr.Wrap(err)
	}
	var users []User
	if err := json.Unmarshal(jsonB, &users); err != nil {
		return serr.Wrap(err)
	}
	s.users = users
	return nil
}

type invite struct {
	ID        string
	UserID    string
	ExpiresAt time.Time
}

func (i *invite) expired() bool {
	return i.ExpiresAt.Before(time.Now())
}

func genRandomID() string {
	var id [16]byte
	rand.Read(id[:])
	return base64.RawURLEncoding.EncodeToString(id[:])
}

type inviteStore struct {
	invites map[string]*invite
	lock    sync.RWMutex
}

var errInviteNotFound = errors.New("invite not found")

func (s *inviteStore) Get(inviteID string) (*invite, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()
	i, found := s.invites[inviteID]
	if !found {
		return nil, serr.Errorf("%w %q", errInviteNotFound, inviteID)
	}
	return i, nil
}

func (s *inviteStore) Create(i *invite) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	if i.ID == "" {
		i.ID = genRandomID()
	}
	if i.ExpiresAt.IsZero() {
		i.ExpiresAt = time.Now().Add(time.Minute * 10)
	}
	if _, found := s.invites[i.ID]; found {
		return serr.Errorf("invite with id %q already exists", i.ID)
	}
	if s.invites == nil {
		s.invites = map[string]*invite{}
	}
	s.invites[i.ID] = i
	return nil
}

func (s *inviteStore) Delete(inviteID string) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	delete(s.invites, inviteID)
	return nil
}

type App struct {
	Config   Config
	WebAuthN *webauthn.WebAuthn

	users              userStore
	invites            inviteStore
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

	a := &App{
		Config:             c,
		WebAuthN:           webauthn,
		registerCookieName: c.CookieNamePrefix + "r",
		loginCookieName:    c.CookieNamePrefix + "l",
		authCookieName:     c.CookieNamePrefix + "a",
	}

	a.users.path = c.UsersFile
	if err := a.users.Reload(); err != nil {
		return nil, err
	}

	if err := a.users.Validate(); err != nil {
		if firstAdmin := a.users.FirstAdmin(); firstAdmin != nil {
			i := invite{UserID: firstAdmin.ID}
			if err := a.invites.Create(&i); err != nil {
				return nil, err
			}
			log.Printf("Created initial invite: %s", i.ID)
		} else {
			return nil, err
		}
	}

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
func (a *App) currentUser(r *http.Request) (*User, error) {
	userID, err := sookie.Get[string](a.Config.CookieSecret, r, a.authCookieName)
	if err != nil {
		return nil, serr.Wrap(err)
	}
	return a.users.ByID(userID)
}

// returns the user from the invite
func (a *App) inviteUser(r *http.Request) (string, *User, error) {
	inviteID := r.PathValue("invite")
	invite, err := a.invites.Get(inviteID)
	if errors.Is(err, errInviteNotFound) || invite != nil && invite.expired() {
		return "", nil, httpError(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			a.pageError(g.Text("No valid invite found.")).Render(w)
		})
	}
	if err != nil {
		return "", nil, err
	}
	user, err := a.users.ByID(invite.UserID)
	if err != nil {
		return "", nil, err
	}
	return inviteID, user, nil
}

func (a *App) inviteGet(w http.ResponseWriter, r *http.Request) error {
	user, err := a.currentUser(r)
	if err != nil {
		return err
	}

	if !slices.Contains(user.Tags, tagAdmin) {
		return serr.Errorf("only admins can create invites")
	}

	// TODO render create invite ui
	a.pageStd("Create Invite", g.Text("Create Invite")).Render(w)
	return nil
}

const inputUserID = "userID"

func (a *App) invitePost(w http.ResponseWriter, r *http.Request) error {
	user, err := a.currentUser(r)
	if err != nil {
		return err
	}

	if !slices.Contains(user.Tags, tagAdmin) {
		return serr.Errorf("only admins can create invites")
	}

	i := &invite{UserID: r.FormValue(inputUserID)}
	if err := a.invites.Create(i); err != nil {
		return err
	}

	// TODO render qr code and share invite ui
	a.pageStd("Invite Created", g.Textf("Invite Created: %+v", i)).Render(w)
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

	jsonB, err := json.MarshalIndent(options, "", "  ")
	if err != nil {
		return serr.Wrap(err)
	}

	a.pageStd("Add Credential",
		g.Group{
			h.H1(g.Textf("Add Credential for %s", user.DisplayName)),
			h.Pre(g.Text(string(jsonB))),
		}).Render(w)
	w.Header().Set("Content-Type", "application/json")
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

	if err := a.users.RegisterCredential(user.ID, credential); err != nil {
		return err
	}

	if err := a.invites.Delete(inviteID); err != nil {
		return err
	}

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

func (a *App) notFound(w http.ResponseWriter, r *http.Request) error {
	w.WriteHeader(http.StatusNotFound)
	a.pageError(g.Text("Not Found")).Render(w)
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
	m.Handle("GET /", a.wrap(a.notFound))
	return &m
}

func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.handler(w, r)
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
				h.StyleEl(g.Raw(appCSS)),
				h.Script(g.Raw(appJS))),
			body))
}

func (a *App) pageStd(title string, body g.Node) g.Node {
	return a.pageShell(title, h.Body(h.Main(body)))
}

func (a *App) pageError(body g.Node) g.Node {
	return a.pageStd("Error", body)
}
