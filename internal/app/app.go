// Package app provides the caddygate application to register & authorize via
// passkeys.
package app

import (
	"bytes"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
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

type RelyingParty struct {
	ID          string   `json:"id,omitempty"`
	DisplayName string   `json:"displayName,omitempty"`
	Origins     []string `json:"origins,omitempty"`
}

type Config struct {
	DataDir          string        `json:"dataDir,omitempty"`
	CookieDomain     string        `json:"cookieDomain,omitempty"`
	CookiePath       string        `json:"cookiePath,omitempty"`
	CookieNamePrefix string        `json:"cookieNamePrefix,omitempty"`
	CookieTTL        time.Duration `json:"cookieTTL,omitempty"`
	Secret           []byte        `json:"secret,omitempty"`
	InviteTTL        time.Duration `json:"inviteTTL,omitempty"`
	AuthBaseURL      string        `json:"authBaseURL,omitempty"`
	SignInURL        string        `json:"signInURL,omitempty"`
	DefaultNext      string        `json:"defaultNext,omitempty"`
	RP               RelyingParty  `json:"rp"`
	Users            []User        `json:"users,omitempty"`
}

type User struct {
	ID   string   `json:"id,omitempty"`
	Name string   `json:"name,omitempty"`
	Tags []string `json:"tags,omitempty"`
}

type UserCredential struct {
	UserID     string              `json:"userID,omitempty"`
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

func IsNotSignedInError(err error) bool {
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

		dir := filepath.Dir(s.path)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return serr.Wrap(err)
			}
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
		if errors.Is(err, os.ErrNotExist) {
			jsonB = []byte(`[]`)
		} else {
			return serr.Wrap(err)
		}
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
	Config Config

	registerCookieSecret []byte
	authCookieSecret     []byte
	signInCookieSecret   []byte
	nextSecret           []byte

	wa                 *webauthn.WebAuthn
	keys               keyStore
	invites            inviteStore
	registerCookieName string
	signInCookieName   string
	authCookieName     string
	handler            http.HandlerFunc
}

func hkdfExpand(key []byte, info string) []byte {
	derived, err := hkdf.Expand(sha256.New, key, info, 32)
	if err != nil {
		panic(err)
	}
	return derived
}

func secureHandler(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-site")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "deny")
		w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
		h.ServeHTTP(w, r)
	}
}

func NewApp(c Config) (*App, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          c.RP.ID,
		RPDisplayName: c.RP.DisplayName,
		RPOrigins:     c.RP.Origins,
	})
	if err != nil {
		return nil, serr.Wrap(err)
	}

	if c.DataDir == "" {
		return nil, serr.Errorf("must specify DataDir in config")
	}
	if c.CookiePath == "" {
		c.CookiePath = "/"
	}
	if c.CookieDomain == "" {
		c.CookieDomain = wa.Config.RPID
	}
	if c.SignInURL == "" {
		c.SignInURL = wa.Config.RPOrigins[0]
	}
	if c.DefaultNext == "" {
		c.DefaultNext = "/"
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
	if len(c.Secret) != 32 {
		return nil, serr.Errorf("must provide a secret of length 32")
	}

	a := &App{
		Config:               c,
		wa:                   wa,
		registerCookieName:   c.CookieNamePrefix + "r",
		signInCookieName:     c.CookieNamePrefix + "l",
		authCookieName:       c.CookieNamePrefix + "a",
		registerCookieSecret: hkdfExpand(c.Secret, "registerCookie"),
		authCookieSecret:     hkdfExpand(c.Secret, "authCookie"),
		signInCookieSecret:   hkdfExpand(c.Secret, "signInCookie"),
		nextSecret:           hkdfExpand(c.Secret, "next"),
	}
	a.invites.ttl = a.Config.InviteTTL

	a.keys.path = filepath.Join(c.DataDir, "keys.json")
	if err := a.keys.Reload(); err != nil {
		return nil, err
	}

	if len(a.Config.Users) == 0 {
		return nil, serr.Errorf("must configure some users")
	}
	if len(a.keys.All()) == 0 {
		for _, u := range a.Config.Users {
			if slices.Contains(u.Tags, tagAdmin) {
				i := &invite{UserID: a.Config.Users[0].ID}
				if err := a.invites.Create(i); err != nil {
					return nil, err
				}
				log.Println("Created initial invite:", a.inviteURL(i))
				break
			}
		}
	}

	var m http.Handler = a.mux()
	m = http.NewCrossOriginProtection().Handler(m)
	m = secureHandler(m)
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

// CurrentUser returns the current logged in User.
// Use IsNotSignedInError to check if the error indicates no signed in User.
func (a *App) CurrentUser(r *http.Request) (User, error) {
	userID, err := sookie.Get[string](a.authCookieSecret, r, a.authCookieName)
	if err != nil {
		return User{}, serr.Wrap(err)
	}
	return a.userByID(userID)
}

func (a *App) SealNextURL(u string) (string, error) {
	return sookie.Seal(a.nextSecret, time.Now().Add(time.Hour*24), u)
}

func (a *App) OpenNextURL(u string) (string, error) {
	return sookie.Open[string](a.nextSecret, u)
}

const pInvite = "/invite"

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

func (a *App) inviteURL(i *invite) string {
	return fmt.Sprintf("%s/register/%s", a.Config.AuthBaseURL, i.ID)
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

	inviteURL := a.inviteURL(i)
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

	options, sessionData, err := a.wa.BeginRegistration(user,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred),
	)
	if err != nil {
		return serr.Wrap(err)
	}

	sookie.Set(a.registerCookieSecret, w, sessionData, a.registerCookie())
	return serr.Wrap(json.NewEncoder(w).Encode(options))
}

const inputJSON = "json"

func (a *App) pkCreatePost(w http.ResponseWriter, r *http.Request) error {
	invite, user, err := a.inviteUser(r)
	if err != nil {
		return err
	}

	sessionData, err := sookie.Get[webauthn.SessionData](
		a.registerCookieSecret, r, a.registerCookieName)
	if err != nil {
		return serr.Wrap(err)
	}

	parsedResponse, err := protocol.ParseCredentialCreationResponseBytes(
		[]byte(r.FormValue(inputJSON)),
	)
	if err != nil {
		return serr.Wrap(err)
	}

	credential, err := a.wa.CreateCredential(
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

	if err := sookie.Set(a.authCookieSecret, w, user.user.ID, a.authCookie()); err != nil {
		return serr.Wrap(err)
	}

	http.Redirect(w, r, a.Config.DefaultNext, http.StatusSeeOther)
	return nil
}

const pPkGet = "/pk-get"

func (a *App) validatePasskeyLogin(r *http.Request) (User, error) {
	sessionData, err := sookie.Get[webauthn.SessionData](
		a.signInCookieSecret, r, a.signInCookieName)
	if err != nil {
		return User{}, serr.Wrap(err)
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponseBytes(
		[]byte(r.FormValue(inputJSON)))
	if err != nil {
		return User{}, serr.Wrap(err)
	}

	user, _, err := a.wa.ValidatePasskeyLogin(a.discoverUser, sessionData, parsedResponse)
	if err != nil {
		return User{}, serr.Wrap(err)
	}
	return user.(waUser).user, nil
}

func (a *App) signInGet(w http.ResponseWriter, r *http.Request) error {
	credentialAssertion, sessionData, err := a.wa.BeginDiscoverableLogin()
	if err != nil {
		return serr.Wrap(err)
	}
	if err := sookie.Set(a.signInCookieSecret, w, sessionData, a.signInCookie()); err != nil {
		return serr.Wrap(err)
	}
	return serr.Wrap(json.NewEncoder(w).Encode(credentialAssertion))
}

const inputNext = "next"

func (a *App) signInPost(w http.ResponseWriter, r *http.Request) error {
	user, err := a.validatePasskeyLogin(r)
	if err != nil {
		return err
	}

	if err := sookie.Set(a.authCookieSecret, w, user.ID, a.authCookie()); err != nil {
		return serr.Wrap(err)
	}

	var nextURL string
	if givenNext := r.FormValue(inputNext); givenNext != "" {
		nextURL, err = a.OpenNextURL(givenNext)
		if err != nil {
			log.Println(err)
		}

	}
	if nextURL == "" {
		nextURL = a.Config.DefaultNext
	}

	http.Redirect(w, r, nextURL, http.StatusSeeOther)
	return nil
}

const pSignOut = "/sign-out"

func (a *App) signOutPost(w http.ResponseWriter, r *http.Request) error {
	sookie.Del(w, r, a.authCookie())
	http.Redirect(w, r, "/", http.StatusSeeOther)
	return nil
}

func (a *App) home(w http.ResponseWriter, r *http.Request) error {
	user, err := a.CurrentUser(r)
	if err != nil {
		if !IsNotSignedInError(err) {
			return err
		}
		return serr.Wrap(a.pageStd("Sign In",
			h.Form(h.Action(pPkGet),
				h.Method(http.MethodPost),
				h.Input(h.Type("hidden"), h.Name(inputNext), h.Value(r.FormValue("next"))),
				h.Input(h.Type("hidden"), h.Name(inputJSON)),
				h.Input(h.Data("pk-get", pPkGet), h.Type("submit"), h.Value("Sign In")),
			),
		).Render(w))
	} else {
		var inviteForm g.Node
		if slices.Contains(user.Tags, tagAdmin) {
			inviteForm = h.Form(h.Class("invite"), h.Action(pInvite),
				h.Method(http.MethodPost),
				h.H3(g.Text("Create Invite")),
				h.Select(h.Name(inputUserID),
					g.Map(a.Config.Users, func(u User) g.Node {
						return h.Option(h.Value(u.ID), g.Text(u.Name))
					})),
				h.Input(h.Type("hidden"), h.Name(inputJSON)),
				h.Input(h.Data("pk-get", pPkGet), h.Type("submit"), h.Value("Create")),
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
	m.Handle("POST "+pInvite, a.wrap(a.invitePost))
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
