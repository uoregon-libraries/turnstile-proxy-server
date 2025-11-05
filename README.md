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
  get from Cloudflare for your turnstile widget.
- `JWT_SIGNING_KEY` should be a long string that can't be guessed.
- `PROXY_TARGET`: the base URL to the protected service's *internal* listener.
  Must like your value for nginx or Caddy's proxy target, this is how TPS finds
  your service so it can proxy to protected content after a turnstile challenge
  is successful.

## Usage

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

## Docker Image

The docker image is set up for production use, and won't be suitable for dev
since you'll have to rebuild the image every time you change anything.

For dev, and even many production use-cases, you're better off just compiling
the binary and shipping it.
