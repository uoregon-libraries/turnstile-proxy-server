# Turnstile Proxy Server

Turnstile Proxy Server, or TPS, is a simple service for putting a Cloudflare
Turnstile page in front of your apps' expensive pages.

The primary use-case is any application where it's infeasible (or just
inconvenient) to add Turnstile pages directly into the codebase, and you need
partial-site Turnstile protection. It's also very useful in cases where you're
not sure which URLs need bot protection; changing your Caddy configuration is
far easier than altering and redeploying your complex app.

## Setup and Configuration

Look at [`env-example`](env-example) for details on the environment variables
you need to set up. Once set, you can simply compile (with `make`) and run.

## Usage

Build via `make`, and run via `./bin/tps serve`. For local dev work, you can
pass `-env-file=./env` or something similar in order to load settings. You can
technically use this on production systems, but you likely want to use podman,
k8s, systemd, etc., where your environment is explicitly set up, or comes from
a file that your TPS user can't read, etc.

By itself, TPS isn't very useful beyond very basic testing:

- You have to start with a reverse proxy of some kind, like Caddy or nginx. TPS
  should not be the only proxy, otherwise it has to protect the entire app, and
  there are better ways to do that. It's also not a full-featured proxy, like
  Caddy or nginx. Don't rely on TPS alone!
- Most of the time, your main proxy will dispatch directly to your protected
  service, and TPS will be involved only for resource-intensive URL patters,
  such as searches. You'll need to configure the TPS environment with this in
  mind.

Also take a look at the example app (`example/...`) for details of how this
could look in a production stack.

**Note**: if you run in debug mode, `internal/templates` must be relative to
your working directory when you run the binary. In release mode, templates are
embedded in the binary so that you don't need to copy them around.

### `tps vacuum` for giant events databases

If you're logging request information, and have a busy site, the log database
will grow way too fast. You'll likely need a very low retention value (e.g.,
`LOG_RETENTION=24h`) or a lot of disk space. Since aggregations are small and
done hourly, and the raw data on a busy site can be essentially useless, you
rarely need a high retention value.

But what if you already have a huge file and change log retention? It won't
shrink because that's how sqlite3 rolls. Enter `tps vacuum`.

`tps vacuum` compacts the event log database and enables incremental
auto-vacuum on it, meaning sqlite releases space from deleted data. Run this
command once and you'll be set!

Note that while running, if the DB got *really* big, you might lose analytics
events. On a 2-gig file we didn't, but just in case be aware it's possible.

## Challenge Tokens

When a client passes a Turnstile challenge, TPS issues a signed JWT in a cookie
so the client isn't re-challenged on every request. Two settings control how
much protection that token gives you against bots that manage to solve a
challenge (e.g., via a CAPTCHA-solving farm): `TOKEN_LIFETIME` and
`TOKEN_REQUEST_BUDGET`.

### Token lifetime

`TOKEN_LIFETIME` controls how long a token is honored before the client must
solve another challenge. The default is four hours. Shorter lifetimes force
bots to re-solve (or re-buy solves) more often; longer lifetimes mean less
friction for legitimate users. There's no revocation, so a leaked or shared
token is good until it expires. *Keep the lifetime short enough that this
doesn't worry you.*

### Request budget

Every token carries a "budget" (`TOKEN_REQUEST_BUDGET`, default `1000`): each
proxied request spends from it, and when it's gone, the client solves a new
challenge. A normal request costs 1. A request whose client IP differs from the
token's *previous* request costs `TOKEN_IP_SWITCH_COST` (default `10`) instead,
making shared tokens across IP-rotating bot farms exceedingly costly.

- A human hitting protected endpoints would need to average a request every 14
  seconds, nonstop, to spend 1000 credits before the four-hour token expires.
- A mobile user whose phone hops between Wi-Fi and cellular, or flaps between
  IPv4 and IPv6, pays 10 per hop, but even if every request switches, they'd
  still have to do a protected request every couple minutes in order to get a
  re-challenge before the four-hour lifetime naturally expires. More likely,
  but not *that* likely, and the worst-case is an extra challenge.
- Bots that switch IPs have a pay for a new Turnstile solve every 100 requests,
  which (hopefully) costs more than it's worth to crawl a site big enough to
  need this kind of protection.

What counts as "a different IP"? The exact address for IPv4, and
the /64 prefix for IPv6 (the typical single-customer delegation, so IPv6
privacy-extension rotation is never a switch).

Budget state lives in TPS's memory, so restarting TPS refreshes every
outstanding token's budget. Restarts should be very rare, so in practice this
won't matter, but if for some reason you restart a lot *and* have bots solving
challenges, know that they get their credits back.

You can set `TOKEN_REQUEST_BUDGET=0` to disable budgets entirely. You shouldn't
do this, as the budget cost in TPS memory is extremely small, and it buys you
some real value against sophisticated bot. But it's something you *can* do.

### Client binding

Tokens are fingerprinted to the client that solved the challenge. A request
presenting a token whose fingerprint doesn't match is treated as having no
token at all, and gets a fresh challenge. This prevents a botnet from sharing a
single success in cases where you disabled the budget side (but don't do that).

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

The request budget assumes requests are *browser navigation only*, and
typically the expensive navigation, not things that are cheap to cache or
static text files, etc.

If a site's CSS, JavaScript, and images are run through through TPS, every page
view spends a dozen or more requests, which isn't great, but worse still is the
fact that a token could expire mid-page-load and the assets then just puke out
403s instead of loading.

If you have assets inside your app's protected paths, configure your front
proxy to *not* proxy them through TPS. With Caddy, for example:

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

## Analytics

TPS exposes some basic endpoints for reporting. There are two endpoints:

- **`/.tps/report`** — The TPS report (no cover sheet needed!)
- **`/.tps/beacon`** — used internally by the challenge page to differentiate
  JS-enabled bots from "dumb" bots (see below)

### Exposing `/.tps/`

TPS is meant to sit on a private network behind your real proxy, and generally
not be routable directly... *except* for `.tps` endpoints. Your front proxy
will need to route `/.tps/` to TPS. You don't really want the general public
sniffing your traffic data, though, even if it is just aggregated bot
protection information.

So there are two rules:

1. `/.tps/report`: disabled entirely unless you set `ADMIN_SECRET`. When set,
   every request must present the secret either as `Authorization: Bearer
   <secret>` or as a `?key=<secret>` query parameter
2. `/.tps/beacon` must always be public, otherwise the "smart vs. dumb" bot
   data can't be collected

On top of the secret, you can also lock the report endpoint down, e.g., we
limit ours to VPN-only. You can also just not expose it and use an ssh tunnel
or curl it from an internal network, e.g.:

```
curl -H 'Authorization: Bearer XYZZY' 'http://tps:8080/.tps/report?period=7d'
```

For a simple IP-based restriction, you might set up Caddy like this:

```caddyfile
# Everybody gets a beacon!
handle /.tps/beacon {
    reverse_proxy tps:8080
}

# Only our super best friends get the rest of .tps
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
- `rendered` — challenge pages whose JavaScript actually ran (the client
  requested `/.tps/beacon`)
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
all*, which is the cheapest way to separate real browsers from the most basic
(dumb) scrapers. At the moment, that latter group is our biggest trouble.

The challenge page pings `/.tps/beacon` as soon as its JavaScript runs, and
that ping is logged as a `rendered` event. Clients that never run JS never hit
the beacon, so `challenged` minus `rendered` is your "dumb bot" floor.
Obviously this can be trivially manipulated, but it doesn't really help bots
any to do that, and even if they do, your site runs fine, you just won't know
how many dumb vs. smart bots you're seeing.

**Note**: if you use [custom challenge templates](#customize-ui), keep the
`navigator.sendBeacon('/.tps/beacon')` snippet from the core template, *or you
lose this signal for those paths*. Okay, not the end of the world, but still a
good thing to keep in mind!

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

## Single-Page Apps

SPAs are a disaster and TPS can't help much.

TPS challenges all requests you send its way, but SPAs do most of their
requests via background REST calls which *can't render a challenge page*. Users
just see a broken app, with no challenge they could solve.

You can protect the initial request to an SPA as you would with any other app,
so long as their REST requests use a different URL than the initial requests.
But that may not buy you enough protection to matter, depending on the kinds of
bots you see, and you'll likely have to do a lot of extra configuration
(outside TPS) to avoid challenging the good bots (particularly difficult in the
GLAM world where we have lots of necessary harvesting beyond just SEO).

---

We added a configuration to challenge navigation-only requests (based on
`Sec-Fetch-Mode`), but (a) this is better done in your main reverse-proxy so
TPS never sees non-navigation requests to begin with, and (b) SPAs. Are. A.
Disaster. The ones we're trying to protect don't use navigation anywhere. Every
request is to a REST API. No HTML. This is literally impossible to protect via
an edge service. TPS is an edge service. Edge services are exactly where you
want your WAF running.

So for SPAs, you're on your own. You'll have to edit page templates and let
your inefficient node runners present and validate challenges whatever way you
see fit. Good luck. I mean that. It's a pain and we're sorry.
