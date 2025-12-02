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
- `PROXY_TARGET`: the base URL to the protected service's *internal* listener.
  Must like your value for nginx or Caddy's proxy target, this is how TPS finds
  your service so it can proxy to protected content after a turnstile challenge
  is successful.
- `DATABASE_DSN`: DSN for the MariaDB database, which stores various stats for
  analysis. e.g., `user:pass@tcp(host:3306)/dbname?parseTime=true`.
  - The `parseTime` argument is important for something I no longer recall, but
    it really is important, so make sure you have that!
- `TEMPLATE_PATH`: If you have custom templates, this is where they'll live.
  See the section below on customizing the UI.

[1]: <https://developers.cloudflare.com/turnstile/troubleshooting/testing/>

## Usage

Build via `make`, and run via `./bin/tps [serve|help]`.

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

TPS was built to solve a real-world problem: our digital exhibit platform was
wrecked by bot traffic (50% uptime on a *good* day). Misbehaving bots rotated
their IP addresses per request, ignored our sitemap, ignored robots.txt, etc.

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
