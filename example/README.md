# TPS Example

This directory houses a complete, working example of TPS protecting an application.

The application is just a simple file server in Go, and serves two HTML pages:
one under `/public` and the other under `/protected`. Feel free to look at the
code if you like (in the "app" subdirectory), but it isn't doing anything
interesting.

The proxy server, running Caddy, is configured so that any requests to
`/protected/*` and `/static-protected/*` are run through TPS, while all other
requests go directly to the app. If you watch the application's logs, you'll
see that it is reporting the proper IP address whether the request goes from
caddy to the app or is routed through TPS first.

Caddy is configured so that it can be your main web server or a secondary proxy
after something like HAProxy, where you might have more institution-wide rules
set up. Be sure to read up on Caddy documentation, though, if your setup is
particularly complex! This example doesn't show how to manage a complicated
real-world app that needs more than a basic protection.

The TPS configuration is very simple, and can be seen in the compose file.

## Accessing the example (HTTPS)

Caddy serves the public listener over https to better mimic production setups.
Over plain HTTP the cookie is not `Secure`, which can hide TLS-specific bugs.

The address comes from the `SITE_HOST` environment variable, defaulting to
`localhost`:

```bash
docker compose up                               # https://localhost
SITE_HOST=192.0.2.10 docker compose up          # https://192.0.2.10 (raw IP)
SITE_HOST=192-0-2-10.nip.io docker compose up   # magic wildcard DNS
```

You can use `nip.io`/`sslip.io` to get a "real" hostname if needed, but beyond
debugging weird problems this won't be necessary for most users.

Caddy issues the certificate from its own internal CA, so your browser will
warn the first time. To silence the warning, trust Caddy's root CA:

```bash
docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./tps-root.crt
# then import tps-root.crt into your browser/OS trust store
```

## Protecting more than one backend (and assets Caddy serves itself)

TPS has exactly one backend: `PROXY_TARGET`. That's deliberate — deciding which
path belongs to which backend is what your front proxy is already good at. This
example protects two very different things anyway:

- `/protected/*` — a page served by the backend app.
- `/static-protected/*` — static files served by **Caddy itself**. Visit
  `/static-protected/` to try it.

The trick is a second, internal-only Caddy listener on `:8081` with no
Turnstile rules. Caddy's public listener routes both protected prefixes to TPS,
TPS challenges them, and everything it verifies is replayed to `:8081`, which
does the routing: `/static-protected/*` is served from disk, everything else is
proxied to the app.

That internal listener is also what keeps Caddy-served assets from looping
forever. Routing `/static-protected/*` through TPS and having TPS proxy back to
the *public* listener would just route the replayed request through TPS again;
the internal listener has no Turnstile rule, so the loop never forms.

The relevant pieces:

- `caddy/Caddyfile` — the public `https://{$SITE_HOST}` listener routes both
  `/protected/*` and `/static-protected/*` to `tps`; the internal `:8081`
  listener serves `/static-protected/*` with `file_server` and proxies the rest
  to the app, with no Turnstile rules anywhere in it.
- `compose.yml` — `tps` has `PROXY_TARGET="http://caddy:8081"`, and port `8081`
  is deliberately not published, so the internal listener is only reachable
  inside the compose network.
- `caddy/static/` — the files Caddy serves on `:8081`.

The alternative, if you'd rather not have TPS proxy back through your front
proxy, is one TPS instance per backend: they're cheap, and each one gets its
own `PROXY_TARGET`.

A single completed challenge unlocks both protected routes (TPS sets a
`tps-jwt` cookie at path `/`).
