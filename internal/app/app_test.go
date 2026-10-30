package app

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daaku/ensure"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// newTestKey returns a new ed25519 seed, as used for the private_key.
func newTestKey() []byte {
	seed := make([]byte, ed25519.SeedSize)
	rand.Read(seed)
	return seed
}

func newTestApp(t testing.TB) *App {
	t.Helper()
	a, err := NewApp(Config{
		Users: Users{
			{ID: "zaphod", Tags: []string{tagAdmin}},
			{ID: "marvin"},
		},
	}, ServeConfig{
		PrivateKey: newTestKey(),
		DataDir:    t.TempDir(),
		RP: RelyingParty{
			ID:          "example.com",
			DisplayName: "Example",
			Origins:     []string{"https://auth.example.com"},
		},
	})
	ensure.Nil(t, err)
	return a
}

func TestSignInRequiresUserVerification(t *testing.T) {
	a := newTestApp(t)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, httptest.NewRequest(http.MethodGet, pPkGet, nil))
	ensure.DeepEqual(t, w.Code, http.StatusOK)
	var assertion protocol.CredentialAssertion
	ensure.Nil(t, json.NewDecoder(w.Body).Decode(&assertion))
	ensure.DeepEqual(t, assertion.Response.UserVerification, protocol.VerificationRequired)
}

func TestCookiesAreSameSiteLax(t *testing.T) {
	a := newTestApp(t)
	for _, c := range []http.Cookie{a.verifier.authCookie(), a.signInCookie(), a.registerCookie()} {
		ensure.DeepEqual(t, c.SameSite, http.SameSiteLaxMode)
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, httptest.NewRequest(http.MethodGet, pPkGet, nil))
	ensure.StringContains(t, w.Header().Get("Set-Cookie"), "SameSite=Lax")
}

func TestIsAllowedNext(t *testing.T) {
	a := newTestApp(t)
	cases := []struct {
		next    string
		allowed bool
	}{
		{"https://example.com/", true},
		{"https://example.com:4430/foo?bar=1", true},
		{"https://admin.example.com/foo", true},
		{"https://ADMIN.Example.com/foo", true},
		{"http://admin.example.com/foo", false},
		{"https://evil.com/", false},
		{"https://evilexample.com/", false},
		{"https://example.com.evil.com/", false},
		{"https://user@admin.example.com/", false},
		{"javascript://example.com/%0aalert(1)", false},
		{"//evil.com/", false},
		{"/foo", false},
	}
	for _, c := range cases {
		t.Run(c.next, func(t *testing.T) {
			ensure.DeepEqual(t, a.verifier.isAllowedNext(c.next), c.allowed)
		})
	}
}

func TestBootstrapInviteIsForFirstAdmin(t *testing.T) {
	a, err := NewApp(Config{
		Users: Users{
			{ID: "marvin"},
			{ID: "zaphod", Tags: []string{tagAdmin}},
		},
	}, ServeConfig{
		PrivateKey: newTestKey(),
		DataDir:    t.TempDir(),
		RP: RelyingParty{
			ID:          "example.com",
			DisplayName: "Example",
			Origins:     []string{"https://auth.example.com"},
		},
	})
	ensure.Nil(t, err)
	ensure.DeepEqual(t, len(a.invites.invites), 1)
	for _, i := range a.invites.invites {
		ensure.DeepEqual(t, i.UserID, "zaphod")
	}
}

func TestInviteTakeIsSingleUse(t *testing.T) {
	var s inviteStore
	s.ttl = time.Hour
	i := &invite{UserID: "marvin"}
	ensure.Nil(t, s.Create(i))

	var wg sync.WaitGroup
	var taken atomic.Int32
	for range 16 {
		wg.Go(func() {
			if _, err := s.Take(i.ID); err == nil {
				taken.Add(1)
			}
		})
	}
	wg.Wait()
	ensure.DeepEqual(t, taken.Load(), int32(1))

	expired := &invite{UserID: "marvin", ExpiresAt: time.Now().Add(-time.Minute)}
	ensure.Nil(t, s.Create(expired))
	_, err := s.Take(expired.ID)
	ensure.True(t, errors.Is(err, errInviteNotFound))
}

func TestRegisterCredentialConcurrent(t *testing.T) {
	a := newTestApp(t)
	const n = 32
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			credential := webauthn.Credential{ID: fmt.Appendf(nil, "credential-%d", i)}
			ensure.Nil(t, a.keys.RegisterCredential(a.verifier.config.Users[1], &credential))
		})
	}
	wg.Wait()
	ensure.DeepEqual(t, len(a.keys.All()), n)

	// what's on disk must match what's in memory
	var reloaded keyStore
	reloaded.path = a.keys.path
	ensure.Nil(t, reloaded.Reload())
	ensure.DeepEqual(t, len(reloaded.All()), n)
}

func TestRegisterCredentialWriteFailure(t *testing.T) {
	a := newTestApp(t)
	// a directory where the file should be makes the write fail
	ensure.Nil(t, os.Mkdir(a.keys.path, 0o700))
	credential := webauthn.Credential{ID: []byte("credential")}
	ensure.NotNil(t, a.keys.RegisterCredential(a.verifier.config.Users[1], &credential))
	ensure.DeepEqual(t, len(a.keys.All()), 0)
}

func TestRegisterCredentialRejectsDuplicateID(t *testing.T) {
	a := newTestApp(t)
	credential := webauthn.Credential{ID: []byte("credential")}
	ensure.Nil(t, a.keys.RegisterCredential(a.verifier.config.Users[1], &credential))
	for _, u := range a.verifier.config.Users {
		err := a.keys.RegisterCredential(u, &credential)
		ensure.True(t, errors.Is(err, errCredentialExists))
	}
	ensure.DeepEqual(t, len(a.keys.All()), 1)
}

func TestRegistrationExcludesExistingCredentials(t *testing.T) {
	a := newTestApp(t)
	credential := webauthn.Credential{ID: []byte("credential")}
	ensure.Nil(t, a.keys.RegisterCredential(a.verifier.config.Users[1], &credential))
	i := &invite{UserID: a.verifier.config.Users[1].ID}
	ensure.Nil(t, a.invites.Create(i))

	w := httptest.NewRecorder()
	a.ServeHTTP(w, httptest.NewRequest(http.MethodGet, pPkCreate+"/"+i.ID, nil))
	ensure.DeepEqual(t, w.Code, http.StatusOK)
	var creation protocol.CredentialCreation
	ensure.Nil(t, json.NewDecoder(w.Body).Decode(&creation))
	ensure.DeepEqual(t, len(creation.Response.CredentialExcludeList), 1)
	ensure.DeepEqual(t, []byte(creation.Response.CredentialExcludeList[0].CredentialID), credential.ID)
}

// testAuthenticator is a minimal software passkey, enough to drive real
// sign-in ceremonies against the app.
type testAuthenticator struct {
	key          *ecdsa.PrivateKey
	credentialID []byte
	user         User
}

const (
	flagUserPresent  = 0x01
	flagUserVerified = 0x04
)

func newTestAuthenticator(t testing.TB, a *App, user User) *testAuthenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ensure.Nil(t, err)
	ta := &testAuthenticator{
		key:          key,
		credentialID: []byte("credential-" + user.ID),
		user:         user,
	}
	ensure.Nil(t, a.keys.RegisterCredential(user, &webauthn.Credential{
		ID:        ta.credentialID,
		PublicKey: ta.coseKey(),
	}))
	return ta
}

// coseKey encodes the public key as a COSE_Key: an EC2 (kty 2) ES256 (alg -7)
// key on P-256 (crv 1).
func (ta *testAuthenticator) coseKey() []byte {
	uncompressed, _ := ta.key.PublicKey.ECDH()
	xy := uncompressed.Bytes()[1:]
	k := []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20}
	k = append(k, xy[:32]...)
	k = append(k, 0x22, 0x58, 0x20)
	return append(k, xy[32:]...)
}

// assert returns the JSON for a navigator.credentials.get() response.
func (ta *testAuthenticator) assert(t testing.TB, a *App, challenge string, flags byte) string {
	t.Helper()
	clientData, err := json.Marshal(map[string]any{
		"type":        "webauthn.get",
		"challenge":   challenge,
		"origin":      a.serve.RP.Origins[0],
		"crossOrigin": false,
	})
	ensure.Nil(t, err)
	rpIDHash := sha256.Sum256([]byte(a.serve.RP.ID))
	authData := append(rpIDHash[:], flags, 0, 0, 0, 0)
	clientDataHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(slices.Clone(authData), clientDataHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, ta.key, digest[:])
	ensure.Nil(t, err)
	b64 := base64.RawURLEncoding.EncodeToString
	response, err := json.Marshal(map[string]any{
		"id":    b64(ta.credentialID),
		"rawId": b64(ta.credentialID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64(clientData),
			"authenticatorData": b64(authData),
			"signature":         b64(signature),
			"userHandle":        b64([]byte(ta.user.ID)),
		},
	})
	ensure.Nil(t, err)
	return string(response)
}

// beginSignIn starts a sign-in ceremony, returning the challenge and the
// session cookies.
func beginSignIn(t testing.TB, a *App) (string, []*http.Cookie) {
	t.Helper()
	w := httptest.NewRecorder()
	a.ServeHTTP(w, httptest.NewRequest(http.MethodGet, pPkGet, nil))
	ensure.DeepEqual(t, w.Code, http.StatusOK)
	var assertion protocol.CredentialAssertion
	ensure.Nil(t, json.NewDecoder(w.Body).Decode(&assertion))
	return assertion.Response.Challenge.String(), w.Result().Cookies()
}

func postSignIn(a *App, cookies []*http.Cookie, response string) *httptest.ResponseRecorder {
	form := url.Values{inputJSON: {response}}
	r := httptest.NewRequest(http.MethodPost, pPkGet, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}

func authCookieFrom(a *App, w *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == a.verifier.authCookieName && c.Value != "" {
			return c
		}
	}
	return nil
}

func TestSignIn(t *testing.T) {
	a := newTestApp(t)
	ta := newTestAuthenticator(t, a, a.verifier.config.Users[1])
	challenge, cookies := beginSignIn(t, a)
	w := postSignIn(a, cookies, ta.assert(t, a, challenge, flagUserPresent|flagUserVerified))
	ensure.DeepEqual(t, w.Code, http.StatusSeeOther)
	auth := authCookieFrom(a, w)
	ensure.NotNil(t, auth)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(auth)
	user, err := a.verifier.CurrentUser(httptest.NewRecorder(), r)
	ensure.Nil(t, err)
	ensure.DeepEqual(t, user.ID, ta.user.ID)
}

func TestSignInWithoutUserVerificationFails(t *testing.T) {
	a := newTestApp(t)
	ta := newTestAuthenticator(t, a, a.verifier.config.Users[1])
	challenge, cookies := beginSignIn(t, a)
	w := postSignIn(a, cookies, ta.assert(t, a, challenge, flagUserPresent))
	ensure.DeepEqual(t, w.Code, http.StatusInternalServerError)
	ensure.True(t, authCookieFrom(a, w) == nil)
}

func TestSignInReplayFails(t *testing.T) {
	a := newTestApp(t)
	ta := newTestAuthenticator(t, a, a.verifier.config.Users[1])
	challenge, cookies := beginSignIn(t, a)
	response := ta.assert(t, a, challenge, flagUserPresent|flagUserVerified)

	w := postSignIn(a, cookies, response)
	ensure.DeepEqual(t, w.Code, http.StatusSeeOther)
	// the session cookie is cleared after use
	ensure.StringContains(t, strings.Join(w.Header().Values("Set-Cookie"), "\n"),
		a.verifier.signInCookieName+"=;")

	// replaying the same cookie and response is rejected
	w = postSignIn(a, cookies, response)
	ensure.DeepEqual(t, w.Code, http.StatusInternalServerError)
	ensure.True(t, authCookieFrom(a, w) == nil)
}

func TestChallengeStoreForgetsExpired(t *testing.T) {
	var s challengeStore
	ensure.Nil(t, s.Spend("a"))
	ensure.True(t, errors.Is(s.Spend("a"), errChallengeSpent))
	s.spent["a"] = time.Now().Add(-time.Second)
	ensure.Nil(t, s.Spend("b"))
	ensure.DeepEqual(t, len(s.spent), 1)
}

func TestRegistrationRequiresDiscoverableCredential(t *testing.T) {
	a := newTestApp(t)
	i := &invite{UserID: a.verifier.config.Users[1].ID}
	ensure.Nil(t, a.invites.Create(i))

	w := httptest.NewRecorder()
	a.ServeHTTP(w, httptest.NewRequest(http.MethodGet, pPkCreate+"/"+i.ID, nil))
	ensure.DeepEqual(t, w.Code, http.StatusOK)
	var creation protocol.CredentialCreation
	ensure.Nil(t, json.NewDecoder(w.Body).Decode(&creation))
	selection := creation.Response.AuthenticatorSelection
	ensure.DeepEqual(t, selection.ResidentKey, protocol.ResidentKeyRequirementRequired)
	ensure.True(t, *selection.RequireResidentKey)
}

// A session created on the machine users sign in on must work on another
// machine (a guard) that only has the shared config, with the public key, and
// neither the private key nor keys.json.
func TestSignInSessionWorksWithOnlyPublicKey(t *testing.T) {
	auth := newTestApp(t)
	guard, err := NewVerifier(auth.verifier.config)
	ensure.Nil(t, err)

	ta := newTestAuthenticator(t, auth, auth.verifier.config.Users[1])
	challenge, cookies := beginSignIn(t, auth)
	w := postSignIn(auth, cookies, ta.assert(t, auth, challenge, flagUserPresent|flagUserVerified))
	ensure.DeepEqual(t, w.Code, http.StatusSeeOther)
	cookie := authCookieFrom(auth, w)
	ensure.NotNil(t, cookie)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(cookie)
	user, err := guard.CurrentUser(httptest.NewRecorder(), r)
	ensure.Nil(t, err)
	ensure.DeepEqual(t, user.ID, ta.user.ID)
}

func TestVerifySession(t *testing.T) {
	key := ed25519.NewKeyFromSeed(newTestKey())
	pub := key.Public().(ed25519.PublicKey)
	valid := SignSession(key, time.Now().Add(time.Hour), "neo")
	userID, err := VerifySession(pub, valid)
	ensure.Nil(t, err)
	ensure.DeepEqual(t, userID, "neo")

	_, err = VerifySession(pub, SignSession(key, time.Now().Add(-time.Second), "neo"))
	ensure.True(t, errors.Is(err, ErrSessionExpired))

	// a different user ID with the original signature
	decoded, err := base64.RawURLEncoding.DecodeString(valid)
	ensure.Nil(t, err)
	tampered := base64.RawURLEncoding.EncodeToString(
		append(decoded[:len(decoded)-len("neo")], "zaphod"...))

	otherKey := ed25519.NewKeyFromSeed(newTestKey())
	for name, raw := range map[string]string{
		"other key": SignSession(otherKey, time.Now().Add(time.Hour), "neo"),
		"tampered":  tampered,
		"short":     base64.RawURLEncoding.EncodeToString(decoded[:ed25519.SignatureSize]),
		"garbage":   "$",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := VerifySession(pub, raw)
			ensure.NotNil(t, err)
			ensure.False(t, errors.Is(err, ErrSessionExpired))
		})
	}
}

func TestNewVerifierErrors(t *testing.T) {
	valid := func() Config {
		return Config{
			PublicKey:    ed25519.NewKeyFromSeed(newTestKey()).Public().(ed25519.PublicKey),
			CookieDomain: "example.com",
			SignInURL:    "https://auth.example.com",
			Users:        Users{{ID: "neo"}},
		}
	}
	cases := []struct {
		name   string
		modify func(*Config)
		err    string
	}{
		{"cookie domain", func(c *Config) { c.CookieDomain = "" }, "must specify cookie_domain"},
		{"sign in url", func(c *Config) { c.SignInURL = "" }, "must specify sign_in_url"},
		{"public key", func(c *Config) { c.PublicKey = c.PublicKey[:16] }, "public_key of length 32"},
		{"users", func(c *Config) { c.Users = nil }, "must configure some users"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			config := valid()
			c.modify(&config)
			_, err := NewVerifier(config)
			ensure.StringContains(t, err.Error(), c.err)
		})
	}
	v, err := NewVerifier(valid())
	ensure.Nil(t, err)
	ensure.DeepEqual(t, v.config.CookiePath, "/")
	ensure.DeepEqual(t, v.authCookieName, "gate-a")
}

func TestNewAppRelyingPartyDefaultsFromSignInURL(t *testing.T) {
	a, err := NewApp(Config{
		CookieDomain: ".example.com",
		SignInURL:    "https://auth.example.com/sign-in",
		Users:        Users{{ID: "neo"}},
	}, ServeConfig{
		PrivateKey: newTestKey(),
		DataDir:    t.TempDir(),
	})
	ensure.Nil(t, err)
	ensure.DeepEqual(t, a.serve.RP.ID, "example.com")
	ensure.DeepEqual(t, a.serve.RP.Origins, []string{"https://auth.example.com"})
	ensure.DeepEqual(t, a.serve.AuthBaseURL, "https://auth.example.com")
}

func TestNewAppConfigDefaultsFromRelyingParty(t *testing.T) {
	a := newTestApp(t)
	ensure.DeepEqual(t, a.verifier.config.CookieDomain, "example.com")
	ensure.DeepEqual(t, a.verifier.SignInURL(), "https://auth.example.com")
}

func TestNewAppKeys(t *testing.T) {
	seed := newTestKey()
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	newApp := func(pub ed25519.PublicKey, seed []byte) (*App, error) {
		return NewApp(Config{
			PublicKey: pub,
			Users:     Users{{ID: "neo"}},
		}, ServeConfig{
			PrivateKey: seed,
			DataDir:    t.TempDir(),
			RP: RelyingParty{
				ID:      "example.com",
				Origins: []string{"https://auth.example.com"},
			},
		})
	}

	a, err := newApp(pub, seed)
	ensure.Nil(t, err)
	ensure.DeepEqual(t, a.verifier.config.PublicKey, pub)

	a, err = newApp(nil, seed)
	ensure.Nil(t, err)
	ensure.DeepEqual(t, a.verifier.config.PublicKey, pub)

	_, err = newApp(pub, nil)
	ensure.StringContains(t, err.Error(), "must provide a private_key of length 32")

	_, err = newApp(pub, newTestKey())
	ensure.StringContains(t, err.Error(), "public_key does not match private_key")
}
