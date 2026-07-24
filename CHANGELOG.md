# Changelog

## v3.0.0

This release takes features *away*. Both of them were TPS doing a reverse
proxy's job, badly: picking a backend by path, and deciding which requests
deserve a challenge. Caddy (or nginx, or whatever you already run in front of
TPS) does both better, and TPS is smaller and easier to reason about without
them. TPS now has one backend and challenges everything you route to it.

### Breaking changes

- **`PROXY_TARGETS` is removed; `PROXY_TARGET` is the only way to set a
  backend.** It takes a single URL (scheme and host required) and every
  verified request goes there. Need more than one backend? Run one TPS per
  backend, or point `PROXY_TARGET` at an internal listener on your front proxy
  and let it route — `example/` now demonstrates the latter.
- **`CHALLENGE_MODE` is removed.** Every request routed to TPS that lacks a
  valid token is challenged. To challenge only top-level navigations, match on
  `Sec-Fetch-Mode` in your front proxy and route only those requests to TPS;
  see "Single-Page Apps" in the README for the Caddy snippet.
- **TPS refuses to start while either variable is set**, with a message
  pointing at the replacement, rather than quietly behaving differently than
  your config asks for. Unset them once you've migrated.
- **The `nav_skip` event outcome is gone**, since nothing produces it anymore.
  Existing `nav_skip` rows in an event log are harmless and reports were never
  built on them.

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
