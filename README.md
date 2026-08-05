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

Critical settings you can't just set to defaults:

- Turnstile site key / secret key must both be set, and require a Cloudflare
  account and Turnstile widget setup
- `PROXY_TARGET`: your protected app. Every request TPS verifies is sent here.
  This should be a host+port that is *not* publicly accessible, otherwise bots
  can skip the protection TPS is trying to provide. Give it a scheme and host
  and nothing else (requests keep their own path when they're forwarded).
- `JWT_SIGNING_KEY`: *must* be set to something bots can't figure out. This
  signs the tokens, and a bot that learns the key can set up fake tokens that
  allow it to bypass TPS entirely. Unlikely, but possible, and really bad if it
  does happen in practice.
- `ADMIN_SECRET`: not critical to be highly secure: there's nothing sensitive
  or dangerous in the admin endpoints, but you probably don't want random
  people looking at your site's challenge numbers, so you may as well make it
  "secure enough". And if we do add anything sensitive in the future, it would
  be gated by this value most likely.

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

## Incorrectly Blocked Users

Some extreme-privacy / extreme-security browsers and plugins can prevent real
users from using sites protected by TPS. This is a limitation of Cloudflare's
Turnstile and there's nothing we can do about it. Certain Safari setups seem to
be particularly affected ("Lockdown Mode").

Cloudflare is protecting your site from bots by guessing what "looks" like a
bot. Often the privacy / security approaches people use look a lot like a bot
trying to cover its tracks.

Unfortunately, you can only choose one: block bots, costing you those users who
are smart enough to be worried about privacy and security, or don't block bots.
For GLAM sites with no budget, we can't keep up with bots.

Make sure you use custom challenge / failure templates with a link to contact
you. If you know enough about the various failure modes, put workarounds in
your challenge / failure pages!

## Docker Image

The docker image is set up for production use, and won't be suitable for dev
since you'll have to rebuild the image every time you change anything.

For dev, and even many production use-cases, you're better off just compiling
the binary and shipping it.

## Challenge Tokens

The wiki page, "[How challenge tokens work][wiki-challenge]," has details, but
briefly: by default each request has a cost and a lifetime. Clients pay per
request, and when that runs out a client has to re-solve the Turnstile
challenge. They also have to re-solve when the lifetime expires.

This is to make sophisticated bots at least have to regularly pay (re-solve
challenges) so they aren't solving a single challenge and using the token
forever to scrape your site.

In practice this means users will see new challenges regularly, but the vast
majority won't notice, as the challenges take a couple seconds and usually
auto-solve.

[wiki-challenge]: <https://github.com/uoregon-libraries/turnstile-proxy-server/wiki/How-challenge-tokens-work>

## Don't protect static assets!

Protected requests must be for *browser navigation only*, and typically only
for the expensive pages, not things that are cheap to render, easy to cache,
static text files, etc.

If a site's CSS, JavaScript, and images are run through through TPS, a token
could expire mid-page-load and the assets then just puke out 403s instead of
loading. This **will break your site for real users**.

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

## Don't protect giant file upload forms!

TPS has to hold data in RAM to replay whatever requests it's protecting. This
is fine for any GET request, and it's usually okay for other requests. But it
can trivially explode in RAM if you're protecting endpoints that expect a large
POST body, such as a file upload.

To limit RAM risks, we have low defaults for the stored challenge data
(`MAX_CHALLENGE_BODY`: per-request limit, and `MAX_CHALLENGE_CACHE`: total RAM
limit). Be careful raising these limits. The max cache should be high enough
that you can hold every bot request's data in RAM while waiting for the
challenge to timeout (five minutes), but not high enough to tip over your
server.

Wherever possible, only protect pages that are GET.

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

**Note**: [custom challenge templates][wiki-ui] that use the `<challenge-form>`
placeholder get the beacon for free — TPS puts it in along with the form. But
if you hand-wrote your challenge markup, keep the
`navigator.sendBeacon('/.tps/beacon')` snippet in it, *or you lose this signal
for those paths*. Okay, not the end of the world, but still a good thing to
keep in mind!

[wiki-ui]: <https://github.com/uoregon-libraries/turnstile-proxy-server/wiki/Customize-UI>

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

We briefly shipped a setting to try and help via `Sec-Fetch-*` header matching,
then ended up removing it: (a) this is better done in your main reverse-proxy
so TPS never sees non-navigation requests to begin with, and (b) SPAs. Are. A.
Disaster. The ones we're trying to protect don't use navigation anywhere. Every
request is to a REST API. No HTML. This is literally impossible to protect via
an edge service. TPS is an edge service. Edge services are exactly where you
want your WAF running.

If you want to use fetch headers to only send navigation requests to TPS, set
up something like this in Caddy:

```
@challenge {
    path /search* /facets*
    header Sec-Fetch-Mode navigate
}
handle @challenge {
    reverse_proxy tps:8080
}
handle {
    reverse_proxy app:8080
}
```

This won't work in all cases, but *might* help some. And you'll really need to
learn about the different fetch headers and how they're used by browsers and
bots. It's obnoxious.

So for SPAs, you're on your own. You'll have to edit page templates and let
your inefficient node runners present and validate challenges whatever way you
see fit. Good luck. I mean that. It's a pain and we're sorry.
