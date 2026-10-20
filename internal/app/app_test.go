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
