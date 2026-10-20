package app

import (
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/daaku/ensure"
	"github.com/go-webauthn/webauthn/protocol"
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
