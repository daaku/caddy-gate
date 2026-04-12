# caddygate

Package caddygate is a caddy module that provides Passkey based authentication.
It isn't a general purpose authentication/authorization module, but instead is
suited for protecting resources for pre-configured users. Users are configured
in `Caddyfile`, and passkeys are written to a JSON file. The idea being that the
configured users, and their passkeys in the JSON file are managed much like any
other configuration file on your system.

## Users & Tags

Users are made up of:

- `id`, a human readable unique username, like `neo`
- `name`, a human readble display name, like `"Anderson"`
- `tags`, optional tags, like `admin billing`.

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

Required parameters:

- `data_dir`, a writable directory to store the data. Currently only contains
  a `keys.json` file containing the passkeys added over time. A directory is
  used to enable atomically replacing the file rather than updating it in place.
- `secret`, a secret used to encrypt/sign cookies and parameters.
- `rp`, various webauthn relying party parameters.
- `users`, configure users.

```Caddyfile
auth.example.com {
	gate {
    data_dir /etc/caddy/gate/example.com
    secret "gd0NcHq9CtemAxiUino3Mtj_rSeJC5k-Uz-tHnI-KKY"
		default_next https://home.caddygate.com:4430
		rp {
			id caddygate.com
			display_name "Caddygate Demo"
			origin https://auth.caddygate.com:4430
		}
		users {
			zaphod "Zaphod" admin
			trillian "Trillan" admin audit
			marvin
		}
	}
}

admin.example.com {
  gate with admin
}

logs.example.com {
  gate
}
```

### All Configuration Options

```Caddyfile
auth.example.com {
  gate serve example.com {
    data_dir /etc/caddy/gate/example.com
    secret "gd0NcHq9CtemAxiUino3Mtj_rSeJC5k-Uz-tHnI-KKY"
    cookie_domain example.com
    cookie_ttl 30d
    auth_base_url https://auth.example.com
    rp {
      id example.com
      display_name "Example"
      origin https://example.com
    }
    users {
      zaphod "Zaphod" admin
      trillian "Trillian" admin
      marvin
    }
  }
}

admin.example.com {
  gate guard example.com with admin
}

logs.example.com {
  gate guard example.com
}
```

### Generate Secret

```sh
head -c32 /dev/random | base64 | tr '+/' '-_' | tr -d '='
```
