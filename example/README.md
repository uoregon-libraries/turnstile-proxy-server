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

## Protecting assets that Caddy serves itself

The example demonstrates two protection patterns, both handled by a single
TPS instance using its `PROXY_TARGETS` config:

- `/protected/*` is proxied to the backend app, as in the simplest TPS setup.
- `/static-protected/*` is proxied to **Caddy itself**, on an internal-only
  listener that serves static files. Visit `/static-protected/` to try it.

The naive single-backend setup loops forever for static assets: if Caddy
routes `/static-protected/*` through TPS, and TPS proxies back to the same
Caddy listener, the replayed request just gets routed through TPS again. To
break the loop, Caddy runs a second, internal-only listener on `:8081` that
serves the static files directly with no Turnstile rule. TPS's `PROXY_TARGETS`
maps `/static-protected/` to `http://caddy:8081`, so once it verifies a
challenge it replays the request against the internal listener and the file
is served — no loop.

The relevant pieces:

- `caddy/Caddyfile` — the public `:8080` listener routes both `/protected/*`
  and `/static-protected/*` to `tps`; the internal `:8081` listener is a
  plain `file_server` with no Turnstile rules.
- `compose.yml` — `tps` has
  `PROXY_TARGETS="/protected/=http://app:8080,/static-protected/=http://caddy:8081"`,
  and port `8081` is deliberately not published, so the internal listener is
  only reachable inside the compose network.
- `caddy/static/` — the files Caddy serves on `:8081`.

A single completed challenge unlocks both protected routes (TPS sets a
`tps-jwt` cookie at path `/`).
