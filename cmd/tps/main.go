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

var bindAddr string
var turnstileSecretKey string
var turnstileSiteKey string
var jwtSigningKey string
var proxyTarget string
var logDBPath string
var logRetention time.Duration
var templatePath string
var tokenLifetime time.Duration
var tokenBindUserAgent bool
var tokenRequestBudget int
var tokenIPSwitchCost int
var maxChallengeBody int64
var maxChallengeCache int64
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
		SetProxyTarget(proxyTarget).
		SetJWTSigningKey(jwtSigningKey).
		SetTokenLifetime(tokenLifetime).
		SetClientBinding(tokenBindUserAgent).
		SetRequestBudget(tokenRequestBudget, tokenIPSwitchCost).
		SetChallengeLimits(maxChallengeBody, maxChallengeCache).
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
