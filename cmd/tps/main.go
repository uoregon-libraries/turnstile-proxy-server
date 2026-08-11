// Package main is our Turnstile proxy server application's core code
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"turnstile-proxy-server/internal/db"
	"turnstile-proxy-server/internal/templates"
	"turnstile-proxy-server/internal/version"

	"github.com/gin-gonic/gin"
	sloggin "github.com/samber/slog-gin"
)

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
	case "key":
		keyCommand(flag.Args()[1:])
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
	fmt.Fprintln(os.Stderr, "Usage: tps [-log-level=debug|info|warn|error] [-env-file=path] [serve|vacuum|key|help]")
}

func help() {
	fmt.Println("Subcommands:")
	fmt.Println("- serve: run the proxy server")
	fmt.Println("- vacuum: compact the event log database at LOG_DB_PATH, returning space freed by")
	fmt.Println("                 pruning to the OS, and enable incremental auto-vacuum so future prunes")
	fmt.Println("                 shrink the file on their own. Safe while a TPS instance is running (requests")
	fmt.Println("                 are never delayed), though some analytics events may be dropped during the")
	fmt.Println("                 rebuild. Needs temporary disk space up to the size of the database.")
	fmt.Println("- key: manage bypass keys — provisioned, rate-limited credentials that skip the")
	fmt.Println("                 challenge (for vetted scrapers). 'tps key' alone shows its own usage;")
	fmt.Println("                 subcommands are add, list, and revoke. Keys live in the event log")
	fmt.Println("                 database, so this needs LOG_DB_PATH.")
	fmt.Println("")
	fmt.Println("Flags:")
	fmt.Println(`- -log-level (optional): log verbosity, one of "debug", "info", "warn", or "error".`)
	fmt.Println(`                 Defaults to "info".`)
	fmt.Println("- -env-file (optional): path to a KEY=VALUE file loaded into the environment before")
	fmt.Println("                 config is read. Real environment variables take precedence.")
	fmt.Println("")
	fmt.Println("Configuration is all via environment variables. See the github repo's env-example")
	fmt.Println("for a comprehensive list and documentation.")
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
	var conf, errs = getenv()
	if len(errs) != 0 {
		logger.Error("Cannot start server", "error", strings.Join(errs, "; "))
		os.Exit(1)
	}

	var store db.Store
	if conf.logDBPath == "" {
		logger.Info("LOG_DB_PATH is not set; event logging is disabled")
		store = db.NewNoopStore()
	} else {
		var err error
		store, err = db.NewStore(conf.logDBPath, conf.logRetention, logger)
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
		SetSecretKey(conf.turnstileSecretKey).
		SetSiteKey(conf.turnstileSiteKey).
		SetProxyTarget(conf.proxyTarget).
		SetJWTSigningKey(conf.jwtSigningKey).
		SetTokenLifetime(conf.tokenLifetime).
		SetClientBinding(conf.tokenBindUserAgent).
		SetRequestBudget(conf.tokenRequestBudget, conf.tokenIPSwitchCost).
		SetChallengeLimits(conf.maxChallengeBody, conf.maxChallengeCache).
		SetAdminSecret(conf.adminSecret).
		SetLogger(logger.With("log.source", "main.Server"))

	server.LoadCoreTemplates("internal/templates/*.go.html", templates.FS)
	server.LoadCustomTemplates(conf.templatePath)

	logger.Info("Starting TPS", "addr", conf.bindAddr)
	var err = server.Run(conf.bindAddr)
	if err != nil {
		logger.Error("Could not start server", "error", err)
		// os.Exit skips the deferred Close, which is what drains queued
		// analytics events; a crashing server shouldn't also lose them
		store.Close()
		os.Exit(1)
	}
}
