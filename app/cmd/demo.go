package main

import (
	"cmp"
	"context"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/daaku/caddygate/app"
	"github.com/daaku/lands"
	"github.com/daaku/serr"
	"github.com/go-webauthn/webauthn/webauthn"
)

func must[T any](t T, err error) T {
	if err != nil {
		panic(err)
	}
	return t
}

func run(ctx context.Context) error {
	config := app.Config{
		UsersFile:    os.Getenv("USERS_FILE"),
		CookieSecret: must(base64.RawURLEncoding.DecodeString(os.Getenv("COOKIE_SECRET"))),
		AuthBaseURL:  cmp.Or(os.Getenv("AUTH_BASE_URL"), "https://localhost:8080"),
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          cmp.Or(os.Getenv("RPID"), "localhost"),
		RPDisplayName: "Caddy Gate Demo",
		RPOrigins:     []string{cmp.Or(os.Getenv("ORIGIN"), "https://localhost:8080")},
	})
	if err != nil {
		return serr.Wrap(err)
	}
	app, err := app.NewApp(config, wa)
	if err != nil {
		return err
	}
	if err := lands.ListenAndServe(ctx, "localhost:8080", app); err != nil {
		return serr.Wrap(err)
	}
	return nil
}

func main() {
	if err := run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}
