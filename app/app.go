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
	"sync"
	"sync/atomic"
	"time"

	"github.com/daaku/serr"
	"github.com/daaku/sookie"
	"github.com/davecgh/go-spew/spew"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	atomicfile "github.com/natefinch/atomic"
	qrsvg "github.com/wamuir/svg-qr-code"
	g "maragu.dev/gomponents"
	h "maragu.dev/gomponents/html"
)

var (
	dump = spew.Dump
	_    = dump
)

const tagAdmin = "admin"

type httpError http.HandlerFunc

func (he httpError) Error() string {
	return "user error"
}

func maxAge(d time.Duration) int {
	return int(d.Seconds())
}

type Config struct {
	KeysFile         string        `json:"keysFile"`
	CookieSecret     []byte        `json:"cookieSecret"`
	CookieDomain     string        `json:"cookieDomain"`
	CookiePath       string        `json:"cookiePath"`
	CookieNamePrefix string        `json:"cookieNamePrefix"`
	CookieTTL        time.Duration `json:"cookieTTL"`
	InviteTTL        time.Duration `json:"inviteTTL"`
	AuthBaseURL      string        `json:"authBaseURL"`
	RP               struct {
		ID          string   `json:"id"`
		DisplayName string   `json:"displayName"`
		Origins     []string `json:"origins"`
	} `json:"rp"`
	Users []User `json:"users"`
}

type User struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

type UserCredential struct {
	UserID     string              `json:"userID"`
	Credential webauthn.Credential `json:"credential"`
}

// waUser implements webauthn.User.
type waUser struct {
	user        User
	credentials []webauthn.Credential
}

func (u waUser) WebAuthnID() []byte                         { return []byte(u.user.ID) }
func (u waUser) WebAuthnName() string                       { return u.user.ID }
func (u waUser) WebAuthnDisplayName() string                { return u.user.Name }
func (u waUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

func isNotSignedInError(err error) bool {
	return errors.Is(err, http.ErrNoCookie) ||
		errors.Is(err, sookie.ErrExpired) ||
		errors.Is(err, ErrUserNotFound)
}

var ErrUserNotFound = errors.New("user not found")

type keyStore struct {
	path string
	lock sync.RWMutex
	keys atomic.Pointer[[]UserCredential]
}

func (s *keyStore) All() []UserCredential {
	return *s.keys.Load()
}

func (s *keyStore) RegisterCredential(user User, credential *webauthn.Credential) error {
	for {
		keys := s.keys.Load()
		newKeys := append(slices.Clone(*keys), UserCredential{
			UserID:     user.ID,
			Credential: *credential,
		})
		if !s.keys.CompareAndSwap(keys, &newKeys) {
			continue // try again
		}

		jsonB, err := json.MarshalIndent(newKeys, "", "  ")
		if err != nil {
			return serr.Wrap(err)
		}

		if err := atomicfile.WriteFile(s.path, bytes.NewReader(jsonB)); err != nil {
			return serr.Wrap(err)
		}
		return nil
	}
}

func (s *keyStore) WaUser(u User) waUser {
	wu := waUser{user: u}
	for _, uc := range s.All() {
		if uc.UserID == u.ID {
			wu.credentials = append(wu.credentials, uc.Credential)
		}
	}
	return wu
}

func (s *keyStore) Reload() error {
	jsonB, err := os.ReadFile(s.path)
	if err != nil {
		return serr.Wrap(err)
	}
	var keys []UserCredential
	if err := json.Unmarshal(jsonB, &keys); err != nil {
		return serr.Wrap(err)
	}
	s.keys.Store(&keys)
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
	ttl     time.Duration
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
		i.ExpiresAt = time.Now().Add(s.ttl)
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

	keys               keyStore
	invites            inviteStore
	registerCookieName string
	signInCookieName   string
	authCookieName     string
	handler            http.HandlerFunc
}

func NewApp(c Config, webauthn *webauthn.WebAuthn) (*App, error) {
	if c.KeysFile == "" {
		return nil, serr.Errorf("must specify KeysFile in config")
	}
	if c.CookiePath == "" {
		c.CookiePath = "/"
	}
	if c.CookieDomain == "" {
		c.CookieDomain = webauthn.Config.GetRPID()
	}
	if c.InviteTTL == 0 {
		c.InviteTTL = time.Hour
	}
	if c.CookieTTL == 0 {
		c.CookieTTL = time.Hour * 24 * 30
	}
	if c.CookieNamePrefix == "" {
		c.CookieNamePrefix = "gate-"
	}

	a := &App{
		Config:             c,
		WebAuthN:           webauthn,
		registerCookieName: c.CookieNamePrefix + "r",
		signInCookieName:   c.CookieNamePrefix + "l",
		authCookieName:     c.CookieNamePrefix + "a",
	}
	a.invites.ttl = a.Config.InviteTTL

	a.keys.path = c.KeysFile
	if err := a.keys.Reload(); err != nil {
		return nil, err
	}

	if len(a.Config.Users) == 0 {
		return nil, serr.Errorf("must configure some users")
	}
	if len(a.keys.All()) == 0 {
		i := invite{UserID: a.Config.Users[0].ID}
		if err := a.invites.Create(&i); err != nil {
			return nil, err
		}
		log.Printf("Created initial invite: %s", i.ID)
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

func (a *App) signInCookie() http.Cookie {
	return http.Cookie{
		Name:     a.signInCookieName,
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
		MaxAge:   maxAge(a.Config.CookieTTL),
		Secure:   true,
		HttpOnly: true,
	}
}

func (a *App) userByID(id string) (User, error) {
	for _, user := range a.Config.Users {
		if user.ID == id {
			return user, nil
		}
	}
	return User{}, serr.Errorf("invalid user id %q: %w", id, ErrUserNotFound)
}

func (a *App) discoverUser(rawID, userHandle []byte) (webauthn.User, error) {
	expectedID := string(userHandle)
	user, err := a.userByID(expectedID)
	if err != nil {
		return nil, err
	}
	return a.keys.WaUser(user), nil
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
	return a.userByID(userID)
}

// returns the user from the invite
func (a *App) inviteUser(r *http.Request) (*invite, waUser, error) {
	inviteID := r.PathValue("invite")
	invite, err := a.invites.Get(inviteID)
	if errors.Is(err, errInviteNotFound) || invite != nil && invite.expired() {
		return nil, waUser{}, httpError(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			a.pageError("Not Found", g.Text("No valid invite found.")).Render(w)
		})
	}
	if err != nil {
		return nil, waUser{}, err
	}
	user, err := a.userByID(invite.UserID)
	if err != nil {
		return nil, waUser{}, err
	}
	return invite, a.keys.WaUser(user), nil
}

const inputUserID = "userID"

func (a *App) invitePost(w http.ResponseWriter, r *http.Request) error {
	user, err := a.validatePasskeyLogin(r)
	if err != nil {
		return httpError(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			a.pageError("Verification Failed", g.Text("Passkey verification failed.")).Render(w)
		})
	}

	if !slices.Contains(user.Tags, tagAdmin) {
		return serr.Errorf("only admins can create invites")
	}

	i := &invite{UserID: r.FormValue(inputUserID)}
	if err := a.invites.Create(i); err != nil {
		return err
	}

	inviteURL := fmt.Sprintf("%s/register/%s", a.Config.AuthBaseURL, i.ID)
	text := fmt.Sprintf("Register key for %s\n\nGo here: ", i.UserID)
	shareJSON, err := json.Marshal(struct {
		URL   string `json:"url"`
		Title string `json:"title"`
		Text  string `json:"text"`
	}{
		URL:   inviteURL,
		Title: text,
		Text:  text,
	})
	if err != nil {
		return serr.Wrap(err)
	}
	svg, err := qrsvg.New(inviteURL)
	if err != nil {
		return serr.Wrap(err)
	}
	svg.Blocksize = 6
	svg.Borderwidth = 2
	return serr.Wrap(a.pageStd("Invite Created",
		g.Group{
			h.H1(g.Text("Invite Created")),
			expiresIn(i.ExpiresAt),
			h.Div(
				h.Button(h.Data("clip", inviteURL), g.Text("Copy URL")),
				g.Text(" "),
				h.Button(h.Data("share", string(shareJSON)), g.Text("Share Invite"))),
			g.Raw(svg.String()),
		},
	).Render(w))
}

var expiredText = g.Text("EXPIRED")

func expiresIn(at time.Time) g.Node {
	inner := expiredText
	if time.Now().Before(at) {
		inner = g.Group{
			g.Text("expires "),
			h.Span(h.Data("rel-time", ""), g.Text(at.Format(time.RFC3339))),
		}
	}
	return h.Span(h.Class("expires-in"), inner)
}

const pPkCreate = "/pk-create"

func (a *App) registerGet(w http.ResponseWriter, r *http.Request) error {
	invite, user, err := a.inviteUser(r)
	if err != nil {
		return err
	}

	pkCreateURL := fmt.Sprintf("%s/%s", pPkCreate, invite.ID)
	a.pageStd("Add Key",
		g.Group{
			h.H1(g.Textf("Welcome, %s", user.user.Name)),
			expiresIn(invite.ExpiresAt),
			h.Button(h.Data("pk-create", pkCreateURL), g.Text("Register")),
		}).Render(w)
	return nil
}

func (a *App) pkCreateGet(w http.ResponseWriter, r *http.Request) error {
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
	return serr.Wrap(json.NewEncoder(w).Encode(options))
}

const inputJSON = "json"

func (a *App) pkCreatePost(w http.ResponseWriter, r *http.Request) error {
	invite, user, err := a.inviteUser(r)
	if err != nil {
		return err
	}

	sessionData, err := sookie.Get[webauthn.SessionData](
		a.Config.CookieSecret, r, a.registerCookieName)
	if err != nil {
		return serr.Wrap(err)
	}

	parsedResponse, err := protocol.ParseCredentialCreationResponseBytes(
		[]byte(r.FormValue(inputJSON)),
	)
	if err != nil {
		return serr.Wrap(err)
	}

	credential, err := a.WebAuthN.CreateCredential(
		user, sessionData, parsedResponse)
	if err != nil {
		return serr.Wrap(err)
	}

	if err := a.keys.RegisterCredential(user.user, credential); err != nil {
		return err
	}

	if err := a.invites.Delete(invite.ID); err != nil {
		return err
	}

	if err := sookie.Set(a.Config.CookieSecret, w, user.user.ID, a.authCookie()); err != nil {
		return serr.Wrap(err)
	}

	// TODO configurable default redirect
	http.Redirect(w, r, "/", http.StatusSeeOther)
	return nil
}

const pPkGet = "/pk-get"

func (a *App) validatePasskeyLogin(r *http.Request) (User, error) {
	sessionData, err := sookie.Get[webauthn.SessionData](
		a.Config.CookieSecret, r, a.signInCookieName)
	if err != nil {
		return User{}, serr.Wrap(err)
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponseBytes(
		[]byte(r.FormValue(inputJSON)))
	if err != nil {
		return User{}, serr.Wrap(err)
	}

	user, _, err := a.WebAuthN.ValidatePasskeyLogin(a.discoverUser, sessionData, parsedResponse)
	if err != nil {
		return User{}, serr.Wrap(err)
	}
	return user.(waUser).user, nil
}

func (a *App) signInGet(w http.ResponseWriter, r *http.Request) error {
	credentialAssertion, sessionData, err := a.WebAuthN.BeginDiscoverableLogin()
	if err != nil {
		return serr.Wrap(err)
	}
	if err := sookie.Set(a.Config.CookieSecret, w, sessionData, a.signInCookie()); err != nil {
		return serr.Wrap(err)
	}
	return serr.Wrap(json.NewEncoder(w).Encode(credentialAssertion))
}

func (a *App) signInPost(w http.ResponseWriter, r *http.Request) error {
	user, err := a.validatePasskeyLogin(r)
	if err != nil {
		return err
	}

	if err := sookie.Set(a.Config.CookieSecret, w, user.ID, a.authCookie()); err != nil {
		return serr.Wrap(err)
	}

	// TODO configured allowed redirect via cookie
	http.Redirect(w, r, "/", http.StatusSeeOther)
	return nil
}

const pSignOut = "/sign-out"

func (a *App) signOutPost(w http.ResponseWriter, r *http.Request) error {
	sookie.Del(w, r, a.authCookie())
	http.Redirect(w, r, "/", http.StatusSeeOther)
	return nil
}

func (a *App) home(w http.ResponseWriter, r *http.Request) error {
	user, err := a.currentUser(r)
	if err != nil {
		if !isNotSignedInError(err) {
			return err
		}
		return serr.Wrap(a.pageStd("Sign In",
			h.Button(h.Data("pk-get", pPkGet), g.Text("Sign In")),
		).Render(w))
	} else {
		var inviteForm g.Node
		if slices.Contains(user.Tags, tagAdmin) {
			inviteForm = h.Form(h.Class("invite"), h.Action("/invite"),
				h.Method(http.MethodPost),
				h.H3(g.Text("Create Invite")),
				h.Select(h.Name(inputUserID),
					g.Map(a.Config.Users, func(u User) g.Node {
						return h.Option(h.Value(u.ID), g.Text(u.Name))
					})),
				h.Input(h.Type("hidden"), h.Name("json")),
				h.Input(h.Data("pk-verify", pPkGet), h.Type("submit"), h.Value("Create")),
			)
		}
		return serr.Wrap(a.pageStd("Welcome back",
			g.Group{
				h.H1(g.Textf("Welcome back, %s.", user.Name)),
				h.Form(h.Action(pSignOut), h.Method(http.MethodPost),
					h.Button(g.Text("Sign Out"))),
				inviteForm,
			},
		).Render(w))
	}
}

func (a *App) notFound(w http.ResponseWriter, r *http.Request) error {
	w.WriteHeader(http.StatusNotFound)
	a.pageError("Not Found", g.Text("Not Found")).Render(w)
	return nil
}

func (a *App) mux() *http.ServeMux {
	var m http.ServeMux
	m.Handle("POST /invite", a.wrap(a.invitePost))
	m.Handle("GET /register/{invite}", a.wrap(a.registerGet))
	m.Handle("GET "+pPkCreate+"/{invite}", a.wrap(a.pkCreateGet))
	m.Handle("POST "+pPkCreate+"/{invite}", a.wrap(a.pkCreatePost))
	m.Handle("GET "+pPkGet, a.wrap(a.signInGet))
	m.Handle("POST "+pPkGet, a.wrap(a.signInPost))
	m.Handle("POST "+pSignOut, a.wrap(a.signOutPost))
	m.Handle("GET /{$}", a.wrap(a.home))
	m.Handle("/", a.wrap(a.notFound))
	return &m
}

func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.handler(w, r)
}

//go:embed app.js
var appJS string

//go:embed app.css
var appCSS string

//go:embed icon-error.svg
var iconError string

func (a *App) pageStd(title string, body g.Node) g.Node {
	return h.Doctype(
		h.HTML(h.Lang("en"),
			h.Head(
				h.Meta(h.Charset("utf-8")),
				h.Meta(h.Name("viewport"), h.Content("width=device-width, initial-scale=1")),
				h.TitleEl(g.Text(title)),
				h.StyleEl(g.Raw(appCSS))),
			h.Body(
				body,
				h.Script(g.Raw(appJS)),
			)))
}

func (a *App) pageError(title string, body g.Node) g.Node {
	return a.pageStd(title,
		h.Div(h.Class("error"),
			h.SVG(g.Attr("viewBox", "0 0 24 24"), g.Raw(iconError)),
			h.Div(body),
		))
}
