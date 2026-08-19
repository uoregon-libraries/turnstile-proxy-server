# Changelog

## Unreleased

### Added

- New config: `MAX_CHALLENGE_BODY` and `MAX_CHALLENGE_CACHE`. These prevent TPS
  from letting bots do trivial DoS attacks by sending unlimited POST requests.
- Bypass keys: provisioned credentials that let vetted clients (careful
  research scrapers, mostly) through TPS without solving a challenge. Requires
  a manual command to provision keys, and requires specifying rate limits to
  avoid badly written scrapers from DoSing your site. `DB_PATH` is required
  to use them, as they have to be persisted and right now that means the event
  log.... For details, see the README's "Bypass Keys" section.

### Fixed

- Requests whose target names another origin are now refused with a 400, e.g.,
  so a link like `https://yoursite.example//evil.example/x` would previously
  redirect to `//evil.example/x` after solving the challenge. With good reverse
  proxy rules (not challenging every path) this was exceedingly unlikely, but
  either way it's impossible now.
- A solved challenge's cached request is now dropped as soon as it's replayed,
  saving RAM and removing a replay risk. Very few bots ever solve a challenge,
  though, so in practice this is a very minor improvement.
- Taking more than five minutes to solve a challenge no longer ends in a 500.
  The challenge form now carries the original request method, so an ordinary
  page view is recovered with a redirect and the visitor never notices. A form
  submission can't be replayed safely, so on expiration users get a message
  saying to resubmit.
- Minor fix in how `solved` counts worked
- A client that disconnects while its just-solved request is being replayed now
  cancels the backend request instead of leaving it running with nobody
  waiting on the response.
- A server that dies on a startup/runtime error no longer discards analytics
  events still queued for the database.
- Secrets in env vars are no longer written to the log (`JWT_SIGNING_KEY` and
  `TURNSTILE_SECRET_KEY`)

### Changed

- Challenged GET requests are no longer buffered or cached while their
  challenge is pending. No POST body, no special replay rules, so this saves
  some RAM and reduces risk during floods.
- `LOG_RETENTION` now defaults to 48 hours instead of 30 days to ensure massive
  traffic isn't running you out of disk space
- `PROXY_TARGET` now gives a useful error if it contains invalid elements (it
  can only contain a scheme and host). It had been silently ignoring other
  parts, now it actually lets you know it's invalid. If your backend needs a
  path prefix, add it in your front proxy.
- `LOG_DB_PATH` is now `DB_PATH`: the database has outgrown its name, holding
  bypass keys, aggregated stats, *and* the event log. The old name will keep
  working until v4.0.0.

### Migration

- Hand-written challenge forms need a new input added: `<input type="hidden"
  name="original_method" value="{{.OriginalMethod}}">`. Use `<challenge-form>`
  instead of building your own forms unless you have a *really* good reason.
- If you used `-env-file`, you may have secrets logged in plaintext. Rotate
  your keys (`JWT_SIGNING_KEY` and `TURNSTILE_SECRET_KEY`) if possible.
- Change `LOG_DB_PATH` to `DB_PATH`

## v3.0.0

This release improves custom templates, fixes some bugs, and also *takes
features away*, so read the "Breaking changes" section carefully!

Both removed features were TPS doing a reverse proxy's job and never should
have been here: use Caddy instead (or nginx or whatever).

### Added

- **A `challenge.go.html` / `failed.go.html` pair at the top of `TEMPLATE_PATH`
  now replaces the built-in pages for every request.** Most servers only need
  one custom look, and don't serve multiple hosts anymore. Previously the only way to get
  that was a `<hostname>/` directory per site you served.
  - You don't have to fix anything. The per-host and per-path directories still
    work and still win when they match: TPS looks for the deepest matching
    path, then the hostname, then your top-level pair, then its own built-in
    page. Challenge and failure pages are looked up separately, so a
    site-specific challenge page can sit alongside a shared failure page.

### Changed

- **Custom challenge templates can just say `<challenge-form></challenge-form>`
  where the widget goes.** TPS expands that placeholder when it loads the
  template, filling in the Turnstile form, the `request_id` field, the script
  that submits the form when the widget succeeds, and the `/.tps/beacon` ping.
  It also adds Cloudflare's `api.js` to the end of your `<head>` (or the top of
  your `<body>` if there's no head), unless your template already loads it.
  Attributes on the element are preserved, so it's still yours to style, and
  anything inside it — a `<noscript>` note, say — is kept after the form.
  - **Nothing breaks.** A challenge template with no `<challenge-form>` element
    is left exactly as-is, so hand-written challenge markup keeps working. The
    failure page is untouched either way.
  - The generated form's id is `tps-challenge-form` and its success callback is
    named `tpsChallengeSolved`; don't reuse those names in a custom template.
  - Two or more placeholders in one template means two Turnstile widgets and two
    forms sharing an id. TPS expands them all and logs a warning at startup.
  - The core challenge template now uses the placeholder itself, so the default
    page and custom pages go through the same code.
- **A custom template that doesn't compile is now skipped, with an error in the
  log, instead of taking TPS down at startup.** The core template covers the
  paths it would have served. An unreadable or unparseable *core* template is
  still fatal, because there'd be nothing left to render.

### Fixed

- **A challenged form submission no longer loses its body.** Oops. This has
  been a bug for a while now.
- **The example stack routes `/.tps/` to TPS.** `example/caddy/Caddyfile` sent
  everything outside the two protected prefixes straight to the app, so the
  challenge page's beacon ping never reached TPS and the example's `rendered`
  counts read zero forever.

### Breaking changes

- **`PROXY_TARGETS` is removed; `PROXY_TARGET` is the only way to set a
  backend.** It takes a single URL (scheme and host required) and every
  verified request goes there. If you need multiple backends:
  - Run one TPS per backend, they're cheap!
  - Point `PROXY_TARGET` at an internal listener that handles routing. This is
    demonstrated in the example app.
- **`CHALLENGE_MODE` is removed.** Every request routed to TPS that lacks a
  valid token is challenged. To challenge only top-level navigations, match on
  `Sec-Fetch-Mode` in your front proxy and route only those requests to TPS;
  see "Single-Page Apps" in the README for the Caddy snippet.
- **TPS refuses to start if you use either of the above deprecated variables**,
  with a message pointing at the replacement. Migrate and unset these.
- **The `nav_skip` event outcome is gone**, since nothing produces it anymore.
  Existing `nav_skip` rows in an event log are harmless and reports were never
  built on them. Unless you used sqlite to manually monitor, you won't care.

### Upgrade notes

- **Single backend, `/` catch-all**: if your `PROXY_TARGETS` was one entry with
  a `/` prefix, this is just a rename — `PROXY_TARGET="<url>"` and you're done.
- **Multiple backends**: route each protected path to its own TPS instance, or
  add an internal-only listener to your front proxy that does the path routing
  and give TPS that as its single `PROXY_TARGET`. The second approach is what
  `example/` uses, including for assets Caddy serves itself.
- **`CHALLENGE_MODE=navigation`**: move the decision into the front proxy. Note
  the behavior isn't identical — TPS treated a *missing* `Sec-Fetch-Mode` as a
  navigation (so header-less scrapers were still challenged), while a
  `header Sec-Fetch-Mode navigate` matcher won't. Add a matcher for the missing
  header if you care about those clients.

## v2.0.0

This release replaces the external MariaDB request log with an embedded SQLite
event log that records every decision TPS makes, then builds analytics on top
of it: a challenge-stats report endpoint and a beacon signal that separates
clients which execute JavaScript from header-only scrapers. The major version
bump is for the logging configuration change (`DATABASE_DSN` is gone); the
proxy and challenge behavior itself is unchanged from 1.1.1.

To sum up: **yes**, you read that right. *We finally have a TPS report.*

### Breaking changes

- **`DATABASE_DSN` is removed and MariaDB is no longer supported.** Logging now
  writes to an SQLite database at **`LOG_DB_PATH`**; leaving it unset disables
  logging entirely, same as an unset `DATABASE_DSN` did before. Old MariaDB
  data is **not** migrated. The `db` service is gone from the compose stacks.
  See Upgrade notes.

### New features

- **Every decision is now logged, not just post-challenge requests.** Each
  request produces one event (`challenged`, `proxied`, `verify_ok`,
  `verify_fail`, `nav_skip`, `challenge_rendered`) with a reason (`no_cookie`,
  `budget_exhausted`, `valid_token`, etc.), so challenges-served-vs-solved is
  finally answerable. Writes are queued and batched in the background: the
  request path never blocks or slows down the proxying behavior.
- **`LOG_RETENTION`** (default `720h`, `0` = keep forever) prunes old raw
  events at startup and hourly thereafter, keeping the database small. New
  databases are created with incremental auto-vacuum, so pruning returns the
  freed disk space to the OS instead of leaving the file at its high-water
  mark.
- **`tps vacuum` subcommand** compacts the event log database at `LOG_DB_PATH`
  and switches it to incremental auto-vacuum — run it once on a database file
  created by an earlier build to shed the space its pruned events still occupy
  (SQLite never shrinks a file on `DELETE` alone). Safe to run alongside a live
  TPS: requests are never delayed, though a long rebuild may drop some
  analytics events.
- **Analytics endpoints under the reserved `/.tps/` path.** A
  collision-resistant prefix (leading dot, à la Anubis's `/.within.website/`)
  that TPS always handles itself and never proxies:
  - **`/.tps/report?period=1d|7d|1m|1y`** returns JSON challenge stats bucketed
    at a sensible granularity for the span (24×1h, 14×12h, 30×1d, 26×2w),
    counting challenges presented, JS-rendered, solved, and failed per bucket.
  - Reports are served from an **hourly rollups table**, updated in the same
    transaction as each event batch, so they stay cheap even on busy servers.
    Rollups are never pruned (a few hundred tiny rows per day), so report
    history reaches back beyond `LOG_RETENTION` — you can cut retention of the
    detailed log to a day or less without losing report data. Existing
    databases are backfilled from their raw events on first open.
- **Smart-vs-dumb-bot signal.** The challenge page now pings **`/.tps/beacon`**
  when its JavaScript executes, recorded as a new `challenge_rendered` event;
  `challenged - rendered` approximates clients that never run JS. Custom
  templates should keep the beacon snippet to preserve the signal.
- **`ADMIN_SECRET`** gates `/.tps/report` (bearer token or `?key=`); unset
  disables it (404), so it's strictly opt-in. The beacon is always public. The
  README's "Analytics" section covers exposing the report endpoint safely,
  since TPS is not meant to face the web directly.

### Upgrade notes

- **Logging config**:
  - Remove `DATABASE_DSN` if you had it set, and drop the MariaDB
    container/service/table if applicable
  - To store stats the new, cool way, set `LOG_DB_PATH` (a file path, e.g.
    `/var/local/tps/data/tps.db`)
  - Note that old MariaDB data is not migrated or preserved in any way. It
    wasn't very useful, it turns out.
- **Front proxy routing**: for `/.tps/report` and `/.tps/beacon` to work, your
  front proxy (Caddy/nginx) must route `/.tps/` to TPS along with the protected
  paths.
- **Custom templates**: add the beacon snippet from the embedded challenge
  template, or the `challenge_rendered` signal (and the report's "rendered"
  column) will always read zero for your pages.

## v1.1.1

This release adds multi-backend routing, substantially hardens challenge tokens
against sharing/replay, introduces an opt-in challenge mode for single-page
apps, and makes the stats database optional, as well as a number of fixes to
the challenge and replay paths.

Many notes below are only relevant if you used something between 1.0.0 and
1.1.1, so if you're migrating from 1.0.0 and notes seem irrelevant or
confusing, don't worry, you can probably ignore them!

### New features

- **Multiple proxy backends.** `PROXY_TARGETS` accepts a comma-separated list
  of `prefix=url` entries; the longest matching path prefix wins (use `/` as a
  catch-all). The single-target `PROXY_TARGET` form still works and is treated
  as `PROXY_TARGETS="/=<url>"` (ignored if `PROXY_TARGETS` is set).
- **Token lifetime, client binding, and request budgets.** Solved challenges
  are now harder to share across bots:
  - `TOKEN_LIFETIME` (default `4h`) controls how long a solved challenge stays
    valid.
  - `TOKEN_BIND_USER_AGENT` (default `true`) hard-binds a token to the solving
    client's User-Agent; a mismatch forces a re-challenge.
  - `TOKEN_REQUEST_BUDGET` (default `1000`, `0` disables) caps how many
    requests a token is good for. A request from a new client IP costs
    `TOKEN_IP_SWITCH_COST` (default `10`) instead of `1`, throttling
    IP-rotating bots. With the budget disabled, the client IP becomes a hard
    binding instead.
- **`CHALLENGE_MODE=navigation` for single-page apps.** Only top-level page
  navigations are challenged; background API/asset requests (anything with a
  `Sec-Fetch-Mode` other than `navigate`) pass straight through. Intended for
  SPAs (DSpace, etc.) whose REST calls can't render a challenge page. Default
  remains `all`. **Note:** this mode has not yet been exercised in production —
  see Known limitations.
- **Optional database.** Leaving `DATABASE_DSN` unset disables request logging
  and runs TPS with no database dependency at all.
- **Local env-file loading** for easier local/dev configuration
- **Logging**: log level is now specified as a flag to `tps`, not derived from
  `GIN_MODE`, so you can get verbose logs without the excessive gin logging.

### Fixes

- GET challenges now **redirect** to the original URL after verification
  instead of replaying inline, fixing broken replays.
- **Conditional headers are stripped** when replaying a challenged request,
  fixing replays that appeared to be broken / empty pages
- Custom templates can be used (the request host wasn't read correctly).
- Challenge and failed-challenge pages now return **HTTP 403** instead of 200.
- The secure cookie flag is only set on TLS connections (so HTTP-fronted dev
  setups work).
- Challenge template rendering fix.

### Known limitations

- **`CHALLENGE_MODE=navigation` is untested in production.** We're pretty sure
  all other features in this release are in active use, but we haven't tested
  navigation mode against a live system yet. (Navigation mode attempts to give
  smart edge-ish protection for single-page apps; see [our README](README.md))
- TPS only trusts **internal/private networks**, and this is **not
  configurable** at this time! The current use-case has been running it on the
  same system as Caddy (or nginx or Apache), but we're aware this could be a
  major limitation for some. See [commit 7fb8e3][commit-7fb8e3] for
  implementation (particularly if you want to offer up a fix).

[commit-7fb8e3]: https://github.com/uoregon-libraries/turnstile-proxy-server/commit/7fb8e303feafeb6c89f67c3b3b472f99463c4452

### Upgrade notes

- No breaking config changes. Existing `PROXY_TARGET` / `DATABASE_DSN` setups
  continue to work. New token-budget and binding behavior is on by default — if
  you proxy static assets through TPS, review `TOKEN_REQUEST_BUDGET` guidance in
  `env-example`/README, since asset-heavy pages can burn budget quickly.
