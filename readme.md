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

## Revoking

To revoke a lost passkey, remove its entry from `keys.json` on the machine
serving sign-in, and reload Caddy there (use `caddy reload --force` if the
Caddyfile itself didn't change). That stops the passkey from signing in again,
but sessions it already created stay valid until they expire (`cookie_ttl`),
because guards don't consult `keys.json`. To end sessions as well, remove the
user from the `Caddyfile`, which ends all of their sessions, or rotate the
`secret`, which ends every session.

## Bootstrapping

The first admin passkey needs to be bootstrapped. At startup, if no users with
passkeys are found, then an invite is created for the first admin, and the URL
is printed in the logs. Use this to register the first passkey. This invite
expires like any other, so use it immediately or restart the server to generate
a fresh invite.

## Caddyfile

The config is split in two:

- The `gate` global option holds the config shared by every machine that
  guards a site, which is all that is needed to check a session.
- The `gate serve` directive goes in the site serving sign-in, and adds the
  config only needed there.

This lets guards run on machines that don't serve sign-in, without them
declaring the sign-in site, or acquiring a certificate for it. Share the
global option between machines, for example with `import`, and only declare the
sign-in site on the one machine that serves it.

Global option parameters:

- `secret` (required), a secret used to encrypt/sign cookies and parameters.
  Anyone who knows it can sign in as any user, so
  [generate your own](#generate-secret) and keep it out of version control, for
  example by passing it in through an environment variable as the examples
  below do. Never reuse the one in the demo `Caddyfile`.
- `cookie_domain` (required), the domain the auth cookie is set on, which
  covers all its subdomains.
- `sign_in_url` (required), where guards send users to sign in.
- `users` (required), configure users.

Serve parameters:

- `data_dir` (required), a writable directory to store the data. Currently only
  contains a `keys.json` file containing the passkeys added over time. A
  directory is used to enable atomically replacing the file rather than
  updating it in place.
- `rp`, various webauthn relying party parameters. The `id` defaults to the
  `cookie_domain`, and the `origin` to that of the `sign_in_url`.

```Caddyfile
{
	gate {
		secret {$CADDY_GATE_SECRET}
		cookie_domain example.com
		sign_in_url https://auth.example.com
		users {
			zaphod "Zaphod" admin
			trillian "Trillian" admin audit
			marvin
		}
	}
}

# only on the machine serving sign-in
auth.example.com {
	gate serve {
		data_dir /etc/caddy/gate/example.com
		default_next https://home.example.com
		rp {
			display_name "Example"
		}
	}
}

# on any machine with the global option
admin.example.com {
	gate with admin
}

logs.example.com {
	gate
}
```

### All Configuration Options

Multiple configs can be defined by naming them, and referring to them by name
in `gate serve` and `gate guard`.

```Caddyfile
{
	gate example.com {
		secret {$CADDY_GATE_SECRET}
		cookie_domain example.com
		cookie_path /
		cookie_name_prefix gate-
		cookie_ttl 30d
		sign_in_url https://auth.example.com
		users {
			zaphod "Zaphod" admin
			trillian "Trillian" admin
			marvin
		}
	}
}

auth.example.com {
	gate serve example.com {
		data_dir /etc/caddy/gate/example.com
		auth_base_url https://auth.example.com
		default_next https://example.com
		invite_ttl 1h
		rp {
			id example.com
			display_name "Example"
			origin https://auth.example.com
		}
	}
}

admin.example.com {
	gate guard example.com with admin {
		header_user_id true
		header_user_tags true
	}
}

logs.example.com {
	gate guard example.com
}
```

### Single Site Config

On a single machine, the global option can instead be given inline in the serve
directive, in which case the `cookie_domain` defaults to the `rp` `id` and the
`sign_in_url` to the first `rp` `origin`:

```Caddyfile
auth.example.com {
	gate {
		data_dir /etc/caddy/gate/example.com
		secret {$CADDY_GATE_SECRET}
		rp {
			id example.com
			display_name "Example"
			origin https://auth.example.com
		}
		users {
			zaphod "Zaphod" admin
		}
	}
}
```

### Generate Secret

```sh
head -c32 /dev/random | base64 | tr '+/' '-_' | tr -d '='
```
