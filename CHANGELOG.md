# Changelog

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
