# Turnstile Proxy Server

Turnstile Proxy Server, or TPS, is a simple service for putting a Cloudflare
Turnstile page in front of your apps.

The primary use-case is any application where it's infeasible (or just
inconvenient) to add Turnstile pages directly into the codebase, and you need
partial-site Turnstile protection.

## Setup and Configuration

Look at `env-example` for details on the environment variables you need to set
up. Once set, you can simply compile (with `make`) and run.

- `GIN_MODE`: Almost always set this to "release". Debug mode isn't useful for
  anybody but TPS devs.
- `BIND_ADDR`: What address and port will TPS listen on?
- `TURNSTILE_SITE_KEY` and `TURNSTILE_SECRET_KEY` are set to whatever keys you
  get from Cloudflare for your turnstile widget, or use test site/secret keys
  from the [Turnstile testing][1] documentation.
- `JWT_SIGNING_KEY` should be a long string that can't be guessed.
- `PROXY_TARGETS`: comma-separated list of `prefix=url` entries selecting a
  backend by request path prefix. Longest matching prefix wins. e.g.
  `"/protected/=http://app:8080,/static-protected/=http://caddy:8081"`. Use
  `/` as a catch-all prefix if you want a single fallback.
- `PROXY_TARGET`: the legacy single-target form, equivalent to
  `PROXY_TARGETS="/=<url>"`. Either `PROXY_TARGETS` or `PROXY_TARGET` must be
  set; if both are set, `PROXY_TARGETS` wins and `PROXY_TARGET` is ignored.
  Like your value for nginx or Caddy's proxy target, the target URL is how TPS
  finds your service so it can proxy to protected content after a turnstile
  challenge is successful.
- `LOG_DB_PATH` (optional): filesystem path to an embedded SQLite database
  where TPS records one decision event per request (challenge served, verified,
  proxied, navigation-mode skip, etc.) for later analysis. The file is created
  if it doesn't exist. If unset, event logging is disabled. Query it with the
  `sqlite3` CLI, e.g.
  `sqlite3 tps.db 'SELECT outcome, reason, COUNT(*) FROM events GROUP BY 1, 2;'`.
- `LOG_RETENTION` (optional): how long to keep logged events, as a Go duration
  string (`"720h"`). Events older than this are pruned at startup and hourly
  thereafter. Defaults to `720h` (30 days); `"0"` keeps events forever.
  Retention applies only to the detailed per-request log: the hourly aggregates
  that feed `/.tps/report` are tiny and are kept forever, so reports still
  cover long periods even with a short retention (e.g. `"24h"`). On databases
  created by TPS 2.x, pruning returns the freed disk space to the OS; a
  database file created by an earlier version keeps reusing its free space
  internally but never shrinks, until you run `tps vacuum` once (see Usage).
- `TEMPLATE_PATH`: If you have custom templates, this is where they'll live.
  See the section below on customizing the UI.
- `TOKEN_LIFETIME` (optional): how long a solved challenge stays valid, as a
  Go duration string like `30m` or `2h`. Defaults to `4h`. See "Challenge
  Tokens" below.
- `TOKEN_BIND_USER_AGENT` (optional): bind tokens to the client's User-Agent
  header. Defaults to `true`. See "Challenge Tokens" below.
- `TOKEN_REQUEST_BUDGET` (optional): how many requests a single solved
  challenge is good for. Defaults to `1000`; `0` disables the budget. See
  "Challenge Tokens" below.
- `TOKEN_IP_SWITCH_COST` (optional): how much of the budget a request costs
  when the client's IP differs from the token's previous request. Defaults
  to `10`; minimum `1`. See "Challenge Tokens" below.
- `CHALLENGE_MODE` (optional): `all` (the default) challenges every request
  that lacks a valid token; `navigation` challenges only top-level page
  navigations and proxies everything else through untouched. See
  "Single-Page Apps" below.

[1]: <https://developers.cloudflare.com/turnstile/troubleshooting/testing/>

## Challenge Tokens

When a client passes a Turnstile challenge, TPS issues a signed JWT in a
cookie so the client isn't re-challenged on every request. Two sets of knobs
control how much protection that token gives you against bots that manage to
solve a challenge once (e.g., via a CAPTCHA-solving farm) and then try to get
as much mileage out of it as possible.

### Token lifetime

`TOKEN_LIFETIME` controls how long a token is honored before the client must
solve another challenge. The default is four hours. Shorter lifetimes force
bots to re-solve (or re-buy solves) more often; longer lifetimes mean less
friction for legitimate users. There's no revocation, so a leaked or shared
token is good until it expires — keep the lifetime short enough that this
doesn't worry you.

### Request budget

Every token carries a budget (`TOKEN_REQUEST_BUDGET`, default `1000`): each
proxied request spends from it, and when it's gone, the client solves a new
challenge. A normal request costs 1. A request whose client IP differs from
the token's *previous* request costs `TOKEN_IP_SWITCH_COST` (default `10`)
instead — switching IPs isn't forbidden, it's just expensive.

This one mechanism handles every client profile differently, and that's the
point:

- A human hitting expensive endpoints (searches, facets) would need to
  average a request every 14 seconds, nonstop, for a 4-hour token to feel
  the default budget. They never will.
- A mobile user whose phone hops between Wi-Fi and cellular, or flaps
  between IPv4 and IPv6, pays 10 per hop. Annoying in budget terms,
  invisible in practice — and crucially, they are *not* re-challenged
  mid-session.
- A bot rotating IPs per request pays the surcharge on every single request:
  1000 budget / 10 per request = 100 requests per solved challenge.
- A sophisticated bot that keeps a separate cookie per IP avoids the
  surcharge but is still capped at 1000 requests per solve, per IP. Before
  budgets, that bot had *unlimited* throughput on each solved IP until the
  token expired.

What counts as "a different IP" is fixed: the exact address for IPv4, and
the /64 prefix for IPv6 (the typical single-customer delegation, so IPv6
privacy-extension rotation is never a switch). These aren't configurable —
loosening them would make rotation within the masked range free, and the
worst bots rotate inside a single /24 or even a handful of addresses. If
strictness is causing pain, the budget and switch cost are the knobs to
reach for, not the masks.

Know the limits of the switch cost: it punishes *rotation*, not *spread*. A
bot that batches its requests per IP (all of IP-A's requests, then all of
IP-B's), or that keeps a separate cookie jar per IP, pays the surcharge
rarely or never. Against those bots the budget cap itself is your only
lever: each solved challenge buys them `TOKEN_REQUEST_BUDGET` requests, full
stop. If sophisticated bots are still causing pain, lower the budget — a
budget of 250 means four times as many solves for the same scrape, and
humans on expensive endpoints still won't notice.

Budget state lives in TPS's memory, so restarting TPS refreshes every
outstanding token's budget. That's a deliberate trade for simplicity —
restarts are rare and bots can't trigger them.

Set `TOKEN_REQUEST_BUDGET=0` to disable budgets entirely. This also changes
IP binding from "charged" back to "enforced" — see below.

### Client binding

Tokens are fingerprinted to the client that solved the challenge. A request
presenting a token whose fingerprint doesn't match is treated as having no
token at all, and gets a fresh challenge. Without this, a single solved
challenge produces a bearer token that an entire botnet can share, no matter
how its members rotate IP addresses.

- **User-Agent** (`TOKEN_BIND_USER_AGENT`, default `true`) is always a hard
  binding: cheap to defeat for a bot that copies headers along with the
  cookie, but it stops lazy token sharing and costs legitimate users
  nothing — browsers don't change their UA mid-session.
- **Client IP** is a hard binding only when the request budget is disabled
  (`TOKEN_REQUEST_BUDGET=0`). With a budget enabled (the default), an IP
  change is charged against the budget instead of rejected, which is far
  kinder to mobile and dual-stack users while still making IP rotation
  expensive for bots. With the budget disabled, the token only works from
  the exact IPv4 address (or IPv6 /64) that solved the challenge, and any
  change forces a re-challenge.

### Don't protect static assets

The request budget assumes requests are *expensive things humans do
deliberately* — searches, report generation, faceted browsing. If TPS sits
in front of pages that also load their CSS, JavaScript, and images through
TPS, every page view spends a dozen or more requests, and a real human can
burn 1000 in half an hour of browsing. Configure your front proxy so static
assets bypass TPS and go straight to the app. With Caddy, for example:

```
@protected {
    path /search* /facets*
    not path *.css *.js *.png *.jpg *.webp *.svg *.woff2 *.ico
}
handle @protected {
    reverse_proxy tps:8080
}
handle {
    reverse_proxy app:8080
}
```

If you genuinely need to protect static files (e.g., the files themselves
are what bots are scraping), raise `TOKEN_REQUEST_BUDGET` to account for the
per-page request multiplier, and remember every asset request passes through
TPS and the backend it proxies to.

## Single-Page Apps

The default mode challenges every request, which breaks single-page apps
(DSpace, anything Angular/React/Vue-based): the requests that fail are the
app's background REST calls, and a `fetch()` call can't render a challenge
page. Users just see a broken app, with no challenge they could solve.

`CHALLENGE_MODE=navigation` fixes this by only challenging *top-level page
navigations* — typing a URL, clicking a link, reloading. Browsers label
every request with a `Sec-Fetch-Mode` header that page JavaScript can
neither forge nor suppress: navigations say `navigate`, while the app's API
calls, scripts, and images say `cors`, `no-cors`, or `same-origin`. In
navigation mode, TPS proxies every non-navigation request straight through,
no token required (or charged against the budget — only navigations spend
it). This also makes the static-asset warning above moot: asset requests
are non-navigations, so they're free.

The user experience: the first page load is a navigation, so the user is
challenged there, solves it once, and the app works. If the token expires
mid-session nothing breaks — the app's background calls don't need a token —
and the user is simply re-challenged on their next real page load.

Understand what this mode does *not* protect:

- The API and asset endpoints are open to any bot that sends a
  `Sec-Fetch-Mode` header the way a browser's `fetch()` does — one static
  header is enough. Dumb scrapers that send no fetch metadata at all are
  still challenged (a missing header is treated as a navigation), and
  browser-mimicking crawler swarms faithfully send `navigate` on page
  fetches, so they're challenged too. But a targeted bot that knows your
  API's shape can harvest it freely. Use this mode when keeping the
  *pages* (and the rendering cost behind them) protected matters more than
  hiding the raw API.
- Requests from pre-2023 browsers (no `Sec-Fetch-Mode` at all: Safari
  before 16.4, Firefox before 90) are all treated as navigations. Those
  browsers still work — they're challenged on page load like anyone else —
  but if their token expires mid-session, their in-page API calls get
  challenge HTML until the next reload.

One deployment note for DSpace specifically: the Angular frontend's
server-side rendering makes its own calls to the REST backend. Route that
server-to-server traffic directly to the backend, not through TPS.

## Analytics

TPS exposes its own endpoints under a reserved, collision-resistant path prefix,
`/.tps/` (the leading dot keeps it clear of real application routes, the same way
Anubis uses `/.within.website/`). Anything under `/.tps/` is always handled by
TPS itself and is never proxied to a backend or challenged.

There are two endpoints:

- **`/.tps/report`** — JSON challenge statistics.
- **`/.tps/beacon`** — used internally by the challenge page (see "Smart vs. dumb
  bots" below). You don't call this yourself.

### Exposing `/.tps/` (read this first)

TPS is meant to sit on a private network behind your real proxy, **not** be
generally reachable from the web. For any of these endpoints to work at all, your
front proxy has to route `/.tps/` to TPS. But `report` reveals traffic data, so
it must not be open to the world. Two rules:

1. **`report` is opt-in and authenticated.** It is disabled entirely (it returns
   `404`) unless you set `ADMIN_SECRET`. When set, every request must present
   the secret either as `Authorization: Bearer <secret>` or as a
   `?key=<secret>` query parameter (the query form makes a plain browser
   bookmark work).
2. **`beacon` is always public.** It only records that a challenged client ran
   JavaScript and carries no data back to the caller, so it's safe to expose. It
   must be reachable by ordinary (challenged) visitors for the smart/dumb signal
   to work.

On top of the secret, lock the report endpoint down at your front proxy. Good
options, roughly in order of preference:

- Don't expose `report` publicly at all — reach it over an SSH tunnel
  or from inside the private network (e.g. `curl -H 'Authorization: Bearer …'
  http://tps:8080/.tps/report?period=7d`).
- Or expose it on an internal-only hostname / port, or behind an IP allowlist
  and/or HTTP basic auth in Caddy/nginx, *in addition to* `ADMIN_SECRET`.

A minimal Caddy sketch that keeps the beacon public but gates the rest by client
IP (the `ADMIN_SECRET` is still required as a second factor):

```caddyfile
# Public: let challenged visitors hit the beacon.
handle /.tps/beacon {
    reverse_proxy tps:8080
}

# Restricted: only the office network can even reach report
# (ADMIN_SECRET is still required on top of this).
@admin path /.tps/*
handle @admin {
    @notallowed not remote_ip 203.0.113.0/24
    respond @notallowed 403
    reverse_proxy tps:8080
}
```

### `/.tps/report`

`GET /.tps/report?period=<1d|7d|1m|1y>` returns counts bucketed at a granularity
that suits the span. `period` defaults to `1d`.

| period | bucket width | rows |
| ------ | ------------ | ---- |
| `1d`   | 1 hour       | 24   |
| `7d`   | 12 hours     | 14   |
| `1m`   | 1 day        | 30   |
| `1y`   | 2 weeks      | 26   |

Buckets are aligned to UTC boundaries, and the most recent (partial) bucket is
included. Each bucket reports four counts:

- `challenged` — challenge pages served (the "raw" number).
- `rendered` — challenge pages whose JavaScript actually ran (see below). The
  difference `challenged - rendered` approximates clients that never execute JS.
- `solved` — Turnstile solutions that verified with Cloudflare.
- `failed` — Turnstile solutions that were submitted but failed verification.

```json
{
  "period": "1d",
  "bucket": "1h0m0s",
  "start": "2026-06-23T10:00:00Z",
  "end": "2026-06-24T10:00:00Z",
  "buckets": [
    { "start": "2026-06-23T10:00:00Z", "challenged": 42, "rendered": 9, "solved": 7, "failed": 1 }
  ]
}
```

Reporting needs the event log, so it returns `503` when `LOG_DB_PATH` is unset.

### Smart vs. dumb bots (`rendered` / the beacon)

`solved` and `failed` already tell you about clients that ran the Turnstile
widget. What they can't tell you is whether a client executes JavaScript *at
all* — the cheapest way to separate real browsers from header-only scrapers. The
embedded challenge page pings `/.tps/beacon` as soon as its JavaScript runs, and
that ping is logged as a `rendered` event. Clients that never run JS never hit
the beacon, so `challenged` minus `rendered` is your "dumb bot" floor.

If you use [custom challenge templates](#customize-ui), keep the
`navigator.sendBeacon('/.tps/beacon')` snippet from the core template, or you
lose this signal for those paths.

## Usage

Build via `make`, and run via `./bin/tps [serve|vacuum|help]`. For local dev
work, you can pass `-env-file=./env` or something similar in order to load
settings.

`tps vacuum` compacts the event log database at `LOG_DB_PATH` (handy when
there's no `sqlite3` CLI on the box) and enables incremental auto-vacuum on it,
so future pruning shrinks the file on its own. Run it once on a database file
carried over from an older TPS to release the space old pruned events still
occupy. It's safe while TPS is running — requests are never delayed, though a
long rebuild can make the server drop some analytics events — and it needs
temporary disk space up to the size of the database file.
You can technically use this on production systems, but you likely want to use
podman, k8s, systemd, etc., where your environment is explicitly set up, or
comes from a file that your TPS user can't read, etc.

By itself, TPS isn't very useful beyond very basic testing.

You have to start with a reverse proxy of some kind, like Caddy or nginx. TPS
should not be the only proxy, otherwise it has to protect the entire app, and
there are better ways to do that. It's also not a full-featured proxy, like
Caddy or nginx. Don't rely on TPS alone!

Most of the time, your main proxy will dispatch directly to your protected
service, and TPS will be involved only for resource-intensive URL patters, such
as searches. You'll need to configure the TPS environment with this in mind.

**Note**: if you run in debug mode, `internal/templates` must be relative to
your working directory when you run the binary. In release mode, templates are
embedded in the binary so that you don't need to copy them around.

Also take a look at the example app (`example/...`) for details of how this
could look in a production stack.

## Real-world usage

### Digital Exhibits

TPS was originally built to solve a single real-world problem: our digital
exhibit platform was wrecked by bot traffic (50% uptime on a *good* day).
Misbehaving bots rotated their IP addresses per request, ignored our sitemap,
ignored robots.txt, etc.

Once we had 20 or so bots each making several requests per minute to our most
expensive endpoints (search and facets), the stack just couldn't keep up. It
was hosted on a shared setup with fairly low resources because it wasn't
expected to see insane levels of traffic.

Building TPS and putting it in front of search and facet requests solved the
resource problems on day 1. Bots still get to crawl our resources, just not our
search pages. Our site stays up. Win-win.

Take a look at our [Digital Exhibits Github project][2] for details of how we
used TPS to basically save a real application.

[2]: <https://github.com/uoregon-libraries/digital-exhibits-spotlight>

### Historic Oregon Newspapers

TPS has also been deployed to protect our largest collection, [Historic Oregon
Newspapers](https://oregonnews.uoregon.edu/). Uptime was never as big an issue
as our exhibits platform, but the server's base resource use was very high, and
for a short time we had to monitor traffic, do reverse-lookups on IP addresses,
and block entire ISPs at the ASN level. Even with millions of IPs blocked, a
surge in traffic, or even just an expensive backend operation (loading a batch
of new newspaper content) occasoinally caused critical services to crash and
not recover.

We had to be a lot more deliberate here: unlike our exhibits platform, HON
doesn't have a single chokepoint, and HON's content is so big there's always
constant "good bot" activity. So we set it up to allow as much harvesting as we
can afford. Bots that identify themselves, stick to our sitemap, and don't DoS
us (harvesting agents being run without throttling) can freely harvest whatever
they like.

With the TPS report, we're now seeing that in any given day there are around
500,000 to a million requests for protected resources. Fewer than 1% of these
render JavaScript, and not even 0.1% actually pass the challenge.

Server load is dramatically smaller, we no longer try to chase ASN-level
blocking, and responsiveness hasn't been this good in years.

## Routing diagnostic traffic to a debug TPS

Sometimes you need to reproduce a problem against a TPS that is built or
configured differently from production -- extra logging, a different
`CHALLENGE_MODE`, a patched binary, a tweaked token budget -- without exposing
that instance to the public or disturbing real traffic. The trick is to run a
second "debug" TPS on its own port and let your front proxy send only *your*
requests to it, keyed on a cookie that only you set.

Say production TPS listens on `:18888` and an always-debug instance listens on
`:18889`. You want `:18889` to handle a request only when it carries the cookie
`debug-tps=secret-key`; everyone else keeps hitting `:18888`. In Caddy, add a
cookie matcher in front of the normal TPS handler and route matching requests
to the debug port:

```caddyfile
https://{$SITE_HOST:localhost} {
  tls internal
  log

  # The paths that go through TPS at all.
  @protected {
    path /protected/* /static-protected/*
  }

  # ...of those, the ones carrying our private debug cookie go to the
  # always-debug TPS on 18889. Use header_regexp (not a loose
  # `header Cookie *...*` substring match) so an unrelated cookie value can't
  # accidentally satisfy it.
  @debug_tps {
    path /protected/* /static-protected/*
    header_regexp Cookie "(^|;\s*)debug-tps=secret-key(\s*;|$)"
  }

  # Order matters: handle blocks are mutually exclusive and evaluated top to
  # bottom, so the more specific debug matcher has to come first.
  handle @debug_tps {
    reverse_proxy 127.0.0.1:18889
  }

  handle @protected {
    reverse_proxy 127.0.0.1:18888
  }

  handle {
    reverse_proxy app:8080
  }
}
```

Set the cookie yourself when you want to opt into the debug path, e.g. from the
browser devtools console (`document.cookie = "debug-tps=secret-key; path=/"`)
or with curl:

```bash
curl -b "debug-tps=secret-key" https://your.host/protected/search?q=test
```

A few things to keep in mind:

- **Keep the debug port private.** Bind the debug TPS to localhost (or an
  internal interface) and never publish it directly. The only way in should be
  through Caddy, which is what enforces the cookie gate. Treat `secret-key` as
  an actual secret -- anyone who knows it can route themselves to the debug
  instance.
- **Tokens are per-instance.** The request budget and IP-switch state live in
  each instance's memory, so a session that bounces between `:18888` and
  `:18889` is tracked separately on each. If you want a token solved on one
  instance to be accepted by the other (so flipping the cookie on/off doesn't
  force a fresh challenge), give both instances the same `JWT_SIGNING_KEY` and
  matching `TOKEN_BIND_*` settings. If you want them fully independent, give
  them different signing keys.
- **It's just a router.** TPS doesn't know about the `debug-tps` cookie at all;
  Caddy makes the routing decision and TPS only ever sees the request that was
  forwarded to it. You can use any cookie name and value you like, as long as
  the matcher and the cookie you set agree.

The most browser-agnostic way to set the cookie is from the dev-tools
JavaScript console (usually `F12`, then the "Console" tab) while you're on the
protected site — cookies are scoped to the site's domain, so you have to be on
it. Paste a line like:

```js
document.cookie = "debug-tps=secret-key; path=/; max-age=86400";
```

- `path=/` makes the cookie apply to every path on the site (the default would
  scope it to just the current page's path).
- `max-age` is in seconds; `86400` is one day, so the cookie sticks around
  instead of vanishing when you close the tab. Use `max-age=0` to delete it when
  you're done debugging.
- If your protected content spans subdomains, add `; domain=.example.com` to
  cover them all.

This works the same in every major browser and in private/incognito windows
(just re-run it for that session). Reload the page after setting the cookie.

## Docker Image

The docker image is set up for production use, and won't be suitable for dev
since you'll have to rebuild the image every time you change anything.

For dev, and even many production use-cases, you're better off just compiling
the binary and shipping it.

## Customize UI

The basic challenge and fail pages are very generic and quite honestly ugly. If
you need to provide a better UI, you can do so with custom templates.

You can choose to set up a `TEMPLATE_PATH` to point to wherever you want to
store these templates, or just stick with the default:
`/var/local/tps/templates`.

Within your template path, a subdirectory is expected to be a hostname,
excluding port, for a site that TPS sits in front of. e.g., you'd start with
`<template path>/localhost/` when doing development.

For the simplest case, just copy and adapt the `*.go.html` files in
`internal/templates`. So you'd have `.../localhost/challenge.go.html` for
the challenge page and `.../localhost/failed.go.html` for the failure
page. TPS will use your custom templates for any requests the browser makes to
localhost.

**Note**: _the hostname is the **public** hostname, not the internal hostname. If
TPS is listening to `front.x.edu` and proxying to `backend.x.edu`, the template
hostname directory is `front.x.edu`, never `backend.x.edu`._

### Matching URL Paths

Under the hostname directory, you can have subdirectories to match specific
paths in a URL. TPS will match the most specific path it can when looking for
custom templates.

So if TPS is protecting everything under `https://front.x/collections/<name>/search`
you could have `<template path>/front.x/challenge.go.html` as your catch-all
challenge, and then individually themed challenges under `<template
path>/front.x/collections/breadmaking/challenge.go.html` for your "Breadmaking"
collection's custom challenge. You can go as deep as you like for the path
names.

### Updating Templates

If you need to change a template, you must restart TPS in a production
environment. Templates will auto-reload on change in dev, but not in
production!
