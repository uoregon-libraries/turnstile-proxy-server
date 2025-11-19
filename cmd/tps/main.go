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

var logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: true}))

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
	fmt.Println("The following environment variables are required:")
	fmt.Println(`- BIND_ADDR: address TPS listens on, e.g., ":8080" to listen on all IPs at port 8080`)
	fmt.Println("- TURNSTILE_SECRET_KEY: your Turnstile secret key")
	fmt.Println("- TURNSTILE_SITE_KEY: your Turnstile site key")
	fmt.Println("- JWT_SIGNING_KEY: a key to sign JWTs with; pick something long and random")
	fmt.Println("- PROXY_TARGET: the internal URL that TPS will be reverse-proxying")
	fmt.Println("- DATABASE_DSN: DSN for the MariaDB database, e.g., user:pass@tcp(host:3306)/dbname?parseTime=true")
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

	var server = NewServer(router, turnstileSiteKey, turnstileSecretKey, jwtSigningKey, proxyTarget, store, logger.With("log.source", "main.Server"))
	server.loadTemplates("internal/templates/*.go.html", templates.FS)

	logger.Info("Starting TPS", "addr", bindAddr)
	err = server.Run(bindAddr)
	if err != nil {
		logger.Error("Could not start server", "error", err)
		os.Exit(1)
	}
}
