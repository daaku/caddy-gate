# caddygate

Package caddygate is a caddy module that provides Passkey based authentication.
It isn't a general purpose authentication/authorization module, but instead is
suited for protecting resources for pre-configured users. Users are configured
in a JSON file, which is written to with passkeys as the are added. The idea
being that the configured users, and their passkeys are managed much like any
configuration files.

## Users & Tags

Users are made up of:

- `id`, a human readable unique username, like `neo`
- `name`, a human readble display name, like `Anderson`
- `tags`, an array of string tags, like `["admin", "billing"]`

Tags can be used to control access.

## Bootstrapping

Invites for adding new passkeys can be created by an `admin`. But the first
admin passkey needs to be bootstrapped. At startup, if no users with passkeys
are found, then an invite is created for the first admin, and the URL is printed
in the logs. Use this to register the first passkey. This invite expires like
any other, so use it immediately or restart the server to generate a fresh
invite.

## Caddyfile

```Caddyfile
auth.example.com {
  caddygate serve example.com {
    keys_file "/etc/caddy/caddygate/example.com.json"
    cookie_secret "gd0NcHq9CtemAxiUino3Mtj_rSeJC5k-Uz-tHnI-KKY"
    cookie_domain "example.com"
    cookie_ttl 30d
    auth_base_url "https://auth.example.com"
    rp {
      id "example.com"
      display_name "Example"
      origin "https://example.com"
    }
    users {
      zaphod "Zaphod" ["admin"]
      marvin "Marvin" ["crew"]
      trillian "Trillan" ["crew"]
    }
  }
}

admin.example.com {
  caddygate guard example.com ["admin"]
}

logs.example.com {
  caddygate guard example.com
}
```

### Relying on defaults

```Caddyfile
auth.example.com {
  caddygate serve {
    keys_file "/etc/caddy/caddygate/example.com.json"
    cookie_secret "gd0NcHq9CtemAxiUino3Mtj_rSeJC5k-Uz-tHnI-KKY"
    rp {
      display_name "Example"
    }
    users {
      zaphod "Zaphod" ["admin"]
      marvin "Marvin" ["crew"]
      trillian "Trillan" ["crew"]
    }
  }
}

admin.example.com {
  caddygate ["admin"]
}

logs.example.com {
  caddygate
}
```

### Generate Cookie Secret

```sh
dd if=/dev/random bs=32 count=1 2>/dev/null | base64 | tr '+/' '-_' | tr -d '='
```
