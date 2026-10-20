package app

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/daaku/ensure"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

func newTestApp(t testing.TB) *App {
	t.Helper()
	secret := make([]byte, 32)
	rand.Read(secret)
	a, err := NewApp(Config{
		DataDir: t.TempDir(),
		Secret:  secret,
		RP: RelyingParty{
			ID:          "example.com",
			DisplayName: "Example",
			Origins:     []string{"https://auth.example.com"},
		},
		Users: Users{
			{ID: "zaphod", Tags: []string{tagAdmin}},
			{ID: "marvin"},
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
	for _, c := range []http.Cookie{a.authCookie(), a.signInCookie(), a.registerCookie()} {
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
			ensure.DeepEqual(t, a.isAllowedNext(c.next), c.allowed)
			sealed, err := a.SealNextURL(c.next)
			ensure.Nil(t, err)
			_, err = a.OpenNextURL(sealed)
			ensure.DeepEqual(t, err == nil, c.allowed)
		})
	}
}

func TestCurrentUserRequiresKnownCredential(t *testing.T) {
	a := newTestApp(t)
	known := webauthn.Credential{ID: []byte("known")}
	ensure.Nil(t, a.keys.RegisterCredential(a.Config.Users[1], &known))

	cases := []struct {
		name    string
		session authSession
		err     error
	}{
		{"known credential", authSession{UserID: "marvin", CredentialID: known.ID}, nil},
		{"removed credential", authSession{UserID: "marvin", CredentialID: []byte("removed")}, ErrCredentialNotFound},
		{"other user's credential", authSession{UserID: "zaphod", CredentialID: known.ID}, ErrCredentialNotFound},
		{"removed user", authSession{UserID: "trillian", CredentialID: known.ID}, ErrUserNotFound},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			ensure.Nil(t, a.setAuthCookie(w, User{ID: c.session.UserID},
				&webauthn.Credential{ID: c.session.CredentialID}))
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			for _, cookie := range w.Result().Cookies() {
				r.AddCookie(cookie)
			}
			user, err := a.CurrentUser(httptest.NewRecorder(), r)
			if c.err == nil {
				ensure.Nil(t, err)
				ensure.DeepEqual(t, user.ID, c.session.UserID)
			} else {
				ensure.True(t, errors.Is(err, c.err))
				ensure.True(t, IsNotSignedInError(err))
			}
		})
	}
}
