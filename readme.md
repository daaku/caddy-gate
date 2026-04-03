# caddygate

Package caddygate is a caddy module that provides Passkey based authentication.
It isn't a general purpose authentication/authorization module, but instead is
suited for protecting resources for pre-configured users. Users are configured
in `Caddyfile`, and passkeys are written to a JSON file. The idea being that the
configured users, and their passkeys in the JSON file are managed much like any
configuration files.

## Users & Tags

Users are made up of:

- `id`, a human readable unique username, like `neo`
- `name`, a human readble display name, like `Anderson`
- `tags`, an array of string tags, like `["admin" "billing"]`

Tags can be used to control access.

## Adding Passkeys / Invites

For any user, adding a new passkey requires an admin to generate an _Invite_.
Once you've configured the user and reloaded the config in Caddy, an admin
can create an invite for that user. The same process can be used repeatedly
for allowing a user to add additional keys.

## Bootstrapping

The first admin passkey needs to be bootstrapped. At startup, if no users with
passkeys are found, then an invite is created for the first admin, and the URL
is printed in the logs. Use this to register the first passkey. This invite
expires like any other, so use it immediately or restart the server to generate
a fresh invite.

## Caddyfile

Required configuration:

- `data_dir`, a writable directory to store the data. Currently only contains
  a `keys.json` file containing the passkeys added over time. A directory is
  used to enable atomically replacing the file rather than updating it in place.
- `cookie_secret`, a secret used to encrypted/sign cookies.
- `users`, configure users.

```Caddyfile
auth.example.com {
  caddygate serve {
    data_dir "/etc/caddy/caddygate/example.com"
    cookie_secret "gd0NcHq9CtemAxiUino3Mtj_rSeJC5k-Uz-tHnI-KKY"
    users {
      zaphod "Zaphod" ["admin" "crew"]
      trillian "Trillan" ["admin" "crew"]
      marvin "Marvin" ["crew"]
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

### All Configuration Options

```Caddyfile
auth.example.com {
  caddygate serve example.com {
    data_dir "/etc/caddy/caddygate/example.com"
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
      zaphod "Zaphod" ["admin" "crew"]
      trillian "Trillan" ["admin" "crew"]
      marvin "Marvin" ["crew"]
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

### Generate Cookie Secret

```sh
dd if=/dev/random bs=32 count=1 2>/dev/null | base64 | tr '+/' '-_' | tr -d '='
```
