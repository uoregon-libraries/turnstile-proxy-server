// Package main is our Turnstile proxy server application's core code
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"
	"turnstile-proxy-server/internal/db"
	"turnstile-proxy-server/internal/templates"
	"turnstile-proxy-server/internal/version"

	"github.com/gin-gonic/gin"
	sloggin "github.com/samber/slog-gin"
)

// proxyRoute is one entry of the parsed PROXY_TARGETS config: a request path
// prefix and the backend URL string to proxy matching requests to.
type proxyRoute struct {
	Prefix string
	Target string
}

var bindAddr string
var turnstileSecretKey string
var turnstileSiteKey string
var jwtSigningKey string
var proxyTargets []proxyRoute
var logDBPath string
var logRetention time.Duration
var templatePath string
var tokenLifetime time.Duration
var tokenBindUserAgent bool
var tokenRequestBudget int
var tokenIPSwitchCost int
var challengeNavigationOnly bool
var adminSecret string

var logger *slog.Logger

// envFile is the path given by the optional -env-file flag: a KEY=VALUE file
// loaded into the environment before config is read (real env vars still win).
var envFile string

func main() {
	var logLevelStr = flag.String("log-level", "info", "log verbosity: debug, info, warn, or error")
	flag.StringVar(&envFile, "env-file", "", "load environment from this KEY=VALUE file before reading config (real env vars win)")
	flag.Usage = printUsage
	flag.Parse()

	var level, ok = parseLogLevel(*logLevelStr)
	if !ok {
		fmt.Fprintf(os.Stderr, "invalid -log-level %q: must be debug, info, warn, or error\n", *logLevelStr)
		os.Exit(2)
	}
	logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))

	fmt.Printf("Turnstile Proxy Server, build %s\n\n", version.Version)

	switch flag.Arg(0) {
	case "serve":
		serve()
	case "vacuum":
		vacuum()
	case "help":
		help()
	default:
		printUsage()
	}
}

// parseLogLevel maps a -log-level flag value to a slog.Level. The bool is false
// for an unrecognized name so the caller can reject it.
func parseLogLevel(name string) (slog.Level, bool) {
	switch strings.ToLower(name) {
	case "debug":
		return slog.LevelDebug, true
	case "info":
		return slog.LevelInfo, true
	case "warn", "warning":
		return slog.LevelWarn, true
	case "error":
		return slog.LevelError, true
	default:
		return slog.LevelInfo, false
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage: tps [-log-level=debug|info|warn|error] [-env-file=path] [serve|vacuum|help]")
}

func help() {
	fmt.Println("Subcommands:")
	fmt.Println("- serve: run the proxy server")
	fmt.Println("- vacuum: compact the event log database at LOG_DB_PATH, returning space freed by")
	fmt.Println("                 pruning to the OS, and enable incremental auto-vacuum so future prunes")
	fmt.Println("                 shrink the file on their own. Safe while a TPS instance is running (requests")
	fmt.Println("                 are never delayed), though some analytics events may be dropped during the")
	fmt.Println("                 rebuild. Needs temporary disk space up to the size of the database.")
	fmt.Println("")
	fmt.Println("Flags:")
	fmt.Println(`- -log-level (optional): log verbosity, one of "debug", "info", "warn", or "error".`)
	fmt.Println(`                 Defaults to "info".`)
	fmt.Println("- -env-file (optional): path to a KEY=VALUE file loaded into the environment before")
	fmt.Println("                 config is read. Real environment variables take precedence.")
	fmt.Println("")
	fmt.Println("Configuration:")
	fmt.Println(`- GIN_MODE (optional): "debug" or "release", defaults to "debug". Controls template`)
	fmt.Println(`                 loading: "release" serves embedded templates, "debug" hot-reloads from disk.`)
	fmt.Println(`- BIND_ADDR (required): address TPS listens on, e.g., ":8080" to listen on all IPs at port 8080`)
	fmt.Println("- TURNSTILE_SECRET_KEY (required): your Turnstile secret key")
	fmt.Println("- TURNSTILE_SITE_KEY (required): your Turnstile site key")
	fmt.Println("- JWT_SIGNING_KEY (required): a key to sign JWTs with; pick something long and random")
	fmt.Println("- PROXY_TARGETS: comma-separated list of \"prefix=url\" entries selecting a backend by request path")
	fmt.Println("                 prefix, e.g., \"/protected/=http://app:8080,/static-protected/=http://caddy:8081\".")
	fmt.Println("                 Longest matching prefix wins. Either PROXY_TARGETS or PROXY_TARGET must be set.")
	fmt.Println("- PROXY_TARGET: legacy single-target form, equivalent to PROXY_TARGETS=\"/=<url>\". Ignored if")
	fmt.Println("                 PROXY_TARGETS is set.")
	fmt.Println("- LOG_DB_PATH (optional): filesystem path to the SQLite event-log database, e.g.,")
	fmt.Println("                 /var/local/tps/tps.db. The file (and its WAL siblings) is created if absent.")
	fmt.Println("                 If unset, event logging is disabled.")
	fmt.Println(`- LOG_RETENTION (optional): how long to keep logged events, as a Go duration ("720h").`)
	fmt.Println(`                 Defaults to "720h" (30 days). "0" keeps events forever (no pruning).`)
	fmt.Println("- TEMPLATE_PATH (optional): path to external templates, defaults to /var/local/tps/templates")
	fmt.Println(`- TOKEN_LIFETIME (optional): how long a solved challenge stays valid, as a Go duration ("30m",`)
	fmt.Println(`                 "2h"). Defaults to "4h". Shorter lifetimes force bots to re-solve more often.`)
	fmt.Println("- TOKEN_BIND_USER_AGENT (optional): bind tokens to the client's User-Agent header so a token")
	fmt.Println("                 stolen or shared by a client with a different UA is rejected. Defaults to true.")
	fmt.Println("- TOKEN_REQUEST_BUDGET (optional): how many requests one solved challenge is good for. Defaults")
	fmt.Println("                 to 1000. 0 disables the budget, which also makes IP binding a hard reject")
	fmt.Println("                 instead of a budget surcharge.")
	fmt.Println("- TOKEN_IP_SWITCH_COST (optional): budget cost of a request whose IP differs from the token's")
	fmt.Println("                 previous request. IPs are tracked exactly for IPv4 and as a /64 for IPv6.")
	fmt.Println("                 Defaults to 10; minimum 1 (an ordinary request).")
	fmt.Println(`- CHALLENGE_MODE (optional): "all" (the default) challenges every request that lacks a valid`)
	fmt.Println(`                 token. "navigation" challenges only top-level page navigations (per the browser's`)
	fmt.Println("                 Sec-Fetch-Mode header) and proxies everything else through with no token needed.")
	fmt.Println("                 Use \"navigation\" for single-page apps whose background API calls can't render a")
	fmt.Println("                 challenge page; note it leaves the API endpoints open to bots. See the README.")
	fmt.Println("- ADMIN_SECRET (optional): shared secret unlocking the /.tps/report endpoint (JSON stats).")
	fmt.Println("                 Unset disables it (404). When set, present it as a bearer token or ?key=. The")
	fmt.Println("                 public /.tps/beacon (JS-execution signal) is unaffected. Route /.tps/ to TPS in")
	fmt.Println("                 your front proxy; see the README for safe exposure.")
}

// vacuum compacts the event log database and flips it into incremental
// auto-vacuum mode. It only needs LOG_DB_PATH, so it deliberately skips the
// full getenv() validation — running it on a box without the serve config
// should work.
func vacuum() {
	applyEnvFile()

	var path = os.Getenv("LOG_DB_PATH")
	if path == "" {
		logger.Error("LOG_DB_PATH is not set; there is no event log database to vacuum")
		os.Exit(1)
	}

	logger.Info("Vacuuming event log database; this can take a while on a large file", "path", path)
	var before, after, err = db.Vacuum(path)
	if err != nil {
		logger.Error("Vacuum failed", "path", path, "error", err)
		os.Exit(1)
	}
	logger.Info("Vacuum complete", "path", path,
		"size_before", fmt.Sprintf("%.1fMB", float64(before)/(1<<20)),
		"size_after", fmt.Sprintf("%.1fMB", float64(after)/(1<<20)))
}

func serve() {
	getenv()

	var store db.Store
	if logDBPath == "" {
		logger.Info("LOG_DB_PATH is not set; event logging is disabled")
		store = db.NewNoopStore()
	} else {
		var err error
		store, err = db.NewStore(logDBPath, logRetention, logger)
		if err != nil {
			logger.Error("Cannot open event log database", "error", err)
			os.Exit(1)
		}
	}
	defer store.Close()

	var router = gin.New()
	var ginLog = logger.With("log.source", "gin.Engine")
	router.Use(sloggin.New(ginLog))
	router.Use(gin.Recovery())

	var server = NewServer(router, store).
		SetSecretKey(turnstileSecretKey).
		SetSiteKey(turnstileSiteKey).
		SetProxyTargets(proxyTargets).
		SetJWTSigningKey(jwtSigningKey).
		SetTokenLifetime(tokenLifetime).
		SetClientBinding(tokenBindUserAgent).
		SetRequestBudget(tokenRequestBudget, tokenIPSwitchCost).
		SetChallengeNavigationOnly(challengeNavigationOnly).
		SetAdminSecret(adminSecret).
		SetLogger(logger.With("log.source", "main.Server"))

	server.LoadCoreTemplates("internal/templates/*.go.html", templates.FS)
	server.LoadCustomTemplates(templatePath)

	logger.Info("Starting TPS", "addr", bindAddr)
	var err = server.Run(bindAddr)
	if err != nil {
		logger.Error("Could not start server", "error", err)
		os.Exit(1)
	}
}
