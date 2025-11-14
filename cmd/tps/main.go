// Package main is our Turnstile proxy server application's core code
package main

import (
	"fmt"
	"log/slog"
	"os"
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
var databaseDSN string
var templatePath string

var logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

func main() {
	fmt.Printf("Turnstile Proxy Server, build %s\n\n", version.Version)

	if len(os.Args) < 2 {
		printUsage()
		return
	}

	switch os.Args[1] {
	case "serve":
		serve()
	case "help":
		help()
	default:
		printUsage()
	}
}

func printUsage() {
	fmt.Println("Usage: tps [serve|help]")
}

func help() {
	fmt.Println("Configuration:")
	fmt.Println(`- BIND_ADDR (required): address TPS listens on, e.g., ":8080" to listen on all IPs at port 8080`)
	fmt.Println("- TURNSTILE_SECRET_KEY (required): your Turnstile secret key")
	fmt.Println("- TURNSTILE_SITE_KEY (required): your Turnstile site key")
	fmt.Println("- JWT_SIGNING_KEY (required): a key to sign JWTs with; pick something long and random")
	fmt.Println("- PROXY_TARGET (required): the internal URL that TPS will be reverse-proxying")
	fmt.Println("- DATABASE_DSN (required): DSN for the MariaDB database, e.g., user:pass@tcp(host:3306)/dbname?parseTime=true")
	fmt.Println("- TEMPLATE_PATH (optional): path to external templates, defaults to /var/local/tps/templates")
}

func serve() {
	getenv()

	var store, err = db.NewStore(databaseDSN, logger)
	if err != nil {
		logger.Error("Cannot open database", "error", err)
		os.Exit(1)
	}
	defer store.Close()

	var router = gin.New()
	var ginLog = logger.With("log.source", "gin.Engine")
	router.Use(sloggin.New(ginLog))
	router.Use(gin.Recovery())

	var server = NewServer(router, proxyTarget, store).
		SetSecretKey(turnstileSecretKey).
		SetSiteKey(turnstileSiteKey).
		SetLogger(logger.With("log.source", "main.Server"))

	server.LoadCoreTemplates("internal/templates/*.go.html", templates.FS)
	server.LoadCustomTemplates(templatePath)

	logger.Info("Starting TPS", "addr", bindAddr)
	err = server.Run(bindAddr)
	if err != nil {
		logger.Error("Could not start server", "error", err)
		os.Exit(1)
	}
}
