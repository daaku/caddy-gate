package main

import (
	"cmp"
	"context"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/daaku/caddy-gate/app"
	"github.com/daaku/lands"
	"github.com/daaku/serr"
)

func must[T any](t T, err error) T {
	if err != nil {
		panic(err)
	}
	return t
}

func run(ctx context.Context) error {
	config := app.Config{
		DataDir:      os.Getenv("DATA_DIR"),
		CookieSecret: must(base64.RawURLEncoding.DecodeString(os.Getenv("COOKIE_SECRET"))),
		AuthBaseURL:  cmp.Or(os.Getenv("AUTH_BASE_URL"), "https://localhost:8080"),
		Users: []app.User{
			{ID: "naitik", Name: "Naitik", Tags: []string{"admin"}},
			{ID: "shweta", Name: "Shweta"},
		},
		RP: app.RelyingParty{
			ID:          cmp.Or(os.Getenv("RPID"), "localhost"),
			DisplayName: "Caddy Gate Demo",
			Origins:     []string{cmp.Or(os.Getenv("ORIGIN"), "https://localhost:8080")},
		},
	}
	app, err := app.NewApp(config)
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
