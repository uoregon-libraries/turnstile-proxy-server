package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"turnstile-proxy-server/internal/db"
)

// keyCommand dispatches the "tps key" subcommands that manage bypass keys.
// Every required setting on "add" really is required — no defaults — so
// provisioning a key means deciding, out loud, how much it may do.
func keyCommand(args []string) {
	if len(args) == 0 {
		printKeyUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "add":
		keyAdd(args[1:])
	case "list":
		keyList()
	case "revoke":
		keyRevoke(args[1:])
	default:
		printKeyUsage()
		os.Exit(2)
	}
}

func printKeyUsage() {
	fmt.Fprintln(os.Stderr, `Usage: tps key <add|list|revoke>

  add -label L -rate N/DUR -burst N -expires WHEN -cidr LIST [-daily-cap N] [-notes TEXT]
      mint a new bypass key (printed once; only its hash is stored)
  list
      show every key with its limits and recent usage
  revoke ID
      permanently kill a key; a running server honors it within `+bypassRefreshInterval.String())
}

// keyStore opens the bypass-key database. Like "tps vacuum" this needs only
// DB_PATH, not the full serve config. Retention 0 keeps the store from pruning
// events out from under a concurrently running server.
func keyStore() db.Store {
	applyEnvFile()
	var path, perr = resolveDBPath()
	if perr != nil {
		logger.Error("Cannot determine the database path", "error", perr)
		os.Exit(1)
	}
	if path == "" {
		logger.Error("DB_PATH is not set")
		os.Exit(1)
	}
	var store, err = db.NewStore(path, 0, logger)
	if err != nil {
		logger.Error("Cannot open database", "path", path, "error", err)
		os.Exit(1)
	}
	return store
}

func keyAdd(args []string) {
	var fs = flag.NewFlagSet("tps key add", flag.ExitOnError)
	var label = fs.String("label", "", "who or what the key is for (required)")
	var rateSpec = fs.String("rate", "", `sustained request rate as "N/DURATION", e.g. "1/2s" or "30/m" (required)`)
	var burst = fs.Int("burst", 0, "requests that may arrive back-to-back before the rate applies (required)")
	var expiresSpec = fs.String("expires", "", `when the key dies: a date like "2027-02-01" (through that day, UTC) or a duration from now like "2160h" (required)`)
	var cidrSpec = fs.String("cidr", "", `comma-separated networks the key works from, e.g. "203.0.113.0/24,198.51.100.7", or "any" (required)`)
	var dailyCap = fs.Int64("daily-cap", 0, "most requests the key may make per UTC day; 0 means uncapped")
	var notes = fs.String("notes", "", "free-form notes stored with the key")
	fs.Parse(args)

	// Collect every problem before reporting, the same courtesy getenv()
	// extends to the serve config.
	var errs []string
	if *label == "" {
		errs = append(errs, "-label is required")
	}

	var ratePerSec float64
	var err error
	if *rateSpec == "" {
		errs = append(errs, `-rate is required, e.g. "1/2s" for one request per two seconds`)
	} else if ratePerSec, err = parseRateSpec(*rateSpec); err != nil {
		errs = append(errs, "-rate: "+err.Error())
	}

	if *burst < 1 {
		errs = append(errs, "-burst is required and must be at least 1")
	}

	var expires time.Time
	if *expiresSpec == "" {
		errs = append(errs, `-expires is required, e.g. "2027-02-01" or "2160h"`)
	} else if expires, err = parseExpirySpec(*expiresSpec, time.Now()); err != nil {
		errs = append(errs, "-expires: "+err.Error())
	}

	var cidrs []string
	if *cidrSpec == "" {
		errs = append(errs, `-cidr is required; use "any" to allow the key from anywhere`)
	} else if cidrs, err = parseCIDRSpec(*cidrSpec); err != nil {
		errs = append(errs, "-cidr: "+err.Error())
	}

	if *dailyCap < 0 {
		errs = append(errs, "-daily-cap must be non-negative")
	}

	if len(errs) != 0 {
		fmt.Fprintln(os.Stderr, "Cannot create key:\n  - "+strings.Join(errs, "\n  - "))
		os.Exit(2)
	}

	var secret = newKeySecret()
	var store = keyStore()
	defer store.Close()

	var id int64
	id, err = store.CreateKey(db.Key{
		Label:      *label,
		KeyHash:    hashKeySecret(secret),
		CIDRs:      cidrs,
		RatePerSec: ratePerSec,
		Burst:      *burst,
		DailyCap:   *dailyCap,
		Notes:      *notes,
		Created:    time.Now(),
		Expires:    expires,
	})
	if err != nil {
		logger.Error("Cannot create key", "error", err)
		os.Exit(1)
	}

	fmt.Printf("Created bypass key %d (%s), expiring %s:\n\n", id, *label,
		expires.UTC().Format(time.RFC3339))
	fmt.Printf("    %s\n\n", secret)
	fmt.Println("This is the only time the key is shown; TPS stores only its hash.")
	fmt.Printf("Clients send it on every request as %q or \"Authorization: Bearer <key>\".\n", bypassKeyHeader+": <key>")
	fmt.Printf("A running server picks it up within %s.\n", bypassRefreshInterval)
}

func keyList() {
	var store = keyStore()
	defer store.Close()

	var keys, err = store.ListKeys()
	if err != nil {
		logger.Error("Cannot list keys", "error", err)
		os.Exit(1)
	}
	if len(keys) == 0 {
		fmt.Println("No bypass keys.")
		return
	}

	// Usage is best-effort color, not the record of truth; a failure to
	// aggregate shouldn't hide the keys themselves.
	usage, uerr := store.KeyUsage()
	if uerr != nil {
		logger.Warn("Cannot read key usage", "error", uerr)
	}

	var now = time.Now()
	var w = tabwriter.NewWriter(os.Stdout, 2, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tLABEL\tSTATUS\tRATE\tBURST\tDAILY CAP\tCIDRS\tEXPIRES\tREQS\t429S\tLAST SEEN\tNOTES")
	for _, k := range keys {
		var status = "active"
		switch {
		case !k.Revoked.IsZero():
			status = "revoked"
		case !now.Before(k.Expires):
			status = "expired"
		}

		var dailyCap = "-"
		if k.DailyCap > 0 {
			dailyCap = strconv.FormatInt(k.DailyCap, 10)
		}
		var networks = "any"
		if len(k.CIDRs) > 0 {
			networks = strings.Join(k.CIDRs, ",")
		}

		var reqs, refused, lastSeen = "-", "-", "-"
		if u, ok := usage[k.ID]; ok {
			reqs = strconv.FormatInt(u.Requests, 10)
			refused = strconv.FormatInt(u.RateLimited, 10)
			lastSeen = u.LastSeen.UTC().Format("2006-01-02 15:04")
		}

		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			k.ID, k.Label, status, formatRate(k.RatePerSec), k.Burst, dailyCap, networks,
			k.Expires.UTC().Format("2006-01-02"), reqs, refused, lastSeen, k.Notes)
	}
	w.Flush()
	fmt.Println("\nREQS/429S/LAST SEEN cover the event log's retention window (LOG_RETENTION).")
}

func keyRevoke(args []string) {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "Usage: tps key revoke ID")
		os.Exit(2)
	}
	var id, err = strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Key id %q must be a number (see 'tps key list')\n", args[0])
		os.Exit(2)
	}

	var store = keyStore()
	defer store.Close()

	if err = store.RevokeKey(id); err != nil {
		if errors.Is(err, db.ErrNoSuchKey) {
			fmt.Fprintf(os.Stderr, "No active key with id %d (see 'tps key list')\n", id)
			os.Exit(1)
		}
		logger.Error("Cannot revoke key", "id", id, "error", err)
		os.Exit(1)
	}
	fmt.Printf("Revoked key %d. A running server stops honoring it within %s.\n", id, bypassRefreshInterval)
}

// newKeySecret mints a fresh bypass key: TPS's namespace prefix and 24 random
// bytes, plenty to make guessing hopeless and hashing (rather than salting
// and stretching) safe.
func newKeySecret() string {
	var b = make([]byte, 24)
	rand.Read(b) // never errors; see crypto/rand
	return bypassKeyPrefix + hex.EncodeToString(b)
}

// parseRateSpec reads a human rate like "1/2s", "30/m", or "10/s" into
// requests per second. The numerator is a whole number of requests; the
// denominator is a Go duration, with a bare unit ("s", "m", "h") standing
// for one of itself.
func parseRateSpec(spec string) (float64, error) {
	var nStr, durStr, ok = strings.Cut(spec, "/")
	if !ok {
		return 0, fmt.Errorf(`rate %q must look like "N/DURATION", e.g. "1/2s" or "30/m"`, spec)
	}
	var n, err = strconv.Atoi(nStr)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("rate %q must start with a whole number of requests, at least 1", spec)
	}
	switch durStr {
	case "s", "m", "h":
		durStr = "1" + durStr
	}
	var dur time.Duration
	if dur, err = time.ParseDuration(durStr); err != nil || dur <= 0 {
		return 0, fmt.Errorf(`rate %q must end with a positive duration, e.g. "2s" or "m"`, spec)
	}
	return float64(n) / dur.Seconds(), nil
}

// formatRate renders a stored per-second rate the way an operator would say
// it: requests per second when it's at least one, otherwise one request per
// so-many seconds.
func formatRate(perSec float64) string {
	if perSec >= 1 {
		return strconv.FormatFloat(perSec, 'g', 3, 64) + "/s"
	}
	if perSec <= 0 {
		return "0/s"
	}
	return fmt.Sprintf("1/%s", time.Duration(float64(time.Second)/perSec).Round(time.Millisecond))
}

// parseExpirySpec reads when a key should die: a date, meaning through the
// end of that day UTC (the operator who types "2027-02-01" means the key
// works on the first), or a Go duration from now.
func parseExpirySpec(spec string, now time.Time) (time.Time, error) {
	if day, err := time.Parse(time.DateOnly, spec); err == nil {
		return day.AddDate(0, 0, 1), nil
	}
	var d, err = time.ParseDuration(spec)
	if err != nil || d <= 0 {
		return time.Time{}, fmt.Errorf(
			`expiry %q must be a date like "2027-02-01" or a positive duration like "2160h"`, spec)
	}
	return now.Add(d), nil
}

// parseCIDRSpec reads the networks a key may be used from. "any" means no
// restriction; otherwise a comma-separated list of CIDRs, where a bare
// address stands for exactly itself. Entries are stored in canonical form so
// what "tps key list" shows is what the server will parse.
func parseCIDRSpec(spec string) ([]string, error) {
	if strings.EqualFold(spec, "any") {
		return nil, nil
	}
	var cidrs []string
	for raw := range strings.SplitSeq(spec, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if addr, err := netip.ParseAddr(raw); err == nil {
			var bits = 32
			if addr.Unmap().Is6() {
				bits = 128
			}
			cidrs = append(cidrs, netip.PrefixFrom(addr.Unmap(), bits).String())
			continue
		}
		var p, err = netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("%q is neither an IP nor a CIDR", raw)
		}
		cidrs = append(cidrs, p.Masked().String())
	}
	if len(cidrs) == 0 {
		return nil, errors.New(`no networks given; use "any" to allow the key from anywhere`)
	}
	return cidrs, nil
}
