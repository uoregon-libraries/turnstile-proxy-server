# TPS Example

This directory houses a complete, working example of TPS protecting an application.

The application is just a simple file server in Go, and serves two HTML pages:
one under `/public` and the other under `/protected`. Feel free to look at the
code if you like (in the "app" subdirectory), but it isn't doing anything
interesting.

The proxy server, running Caddy, is configured so that any requests to
`/protected/*` are run through TPS, while all other requests go directly to the
app. If you watch the application's logs, you'll see that it is reporting the
proper IP address whether the request goes from caddy to the app or is routed
through TPS first.

The TPS configuration is very simple, and can be seen in the compose file.
