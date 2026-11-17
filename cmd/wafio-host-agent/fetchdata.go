package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/wafio/wafio-cp-backend/shared/geo"
)

var hostFetchDataCmd = &cobra.Command{
	Use:   "fetch-data",
	Short: "Download security data required by the host agent",
	Long: `Download security data required by the host/eBPF agent onto this machine.

Run this command once after deploying the agent binary, and periodically
to keep data up-to-date. No control-plane connection is needed.

Components downloaded (host-agent profile):
  geoip-country  GeoIP country database for XDP geo-blocking

GeoIP provider:
  • Default: DB-IP free databases (no account or license key required)
  • With --maxmind-key: MaxMind GeoLite2 (free account at maxmind.com)

After running, start the agent with:
  --geoip-db  <dir>/geoip/country.mmdb`,
	RunE: runHostFetchData,
}

var (
	hostFetchDir        string
	hostFetchMaxMindKey string
	hostFetchForce      bool
	hostFetchOnly       string
	hostFetchProfile    string
)

// The host agent downloads one component: the GeoIP country database.
const (
	hostFetchProfileName = "host-agent"
	hostFetchComponent   = "geoip-country"
)

func init() {
	hostFetchDataCmd.Flags().StringVar(&hostFetchDir, "dir", "/etc/wafio/security-data",
		"Directory to store downloaded security data")
	hostFetchDataCmd.Flags().StringVar(&hostFetchMaxMindKey, "maxmind-key", "",
		"MaxMind GeoLite2 license key (free at maxmind.com; overrides WAFIO_MAXMIND_LICENSE_KEY env)")
	hostFetchDataCmd.Flags().BoolVar(&hostFetchForce, "force", false,
		"Re-download even if files already exist")
	hostFetchDataCmd.Flags().StringVar(&hostFetchOnly, "only", "",
		"Comma-separated subset to download: geoip-country (alias geoip)")
	hostFetchDataCmd.Flags().StringVar(&hostFetchProfile, "profile", hostFetchProfileName,
		`Preset component set; only "host-agent" exists here (the WAF set is wafio-waf-agent fetch-data)`)

	rootCmd.AddCommand(hostFetchDataCmd)
}

func runHostFetchData(_ *cobra.Command, _ []string) error {
	if p := strings.TrimSpace(hostFetchProfile); p != "" && p != hostFetchProfileName {
		return fmt.Errorf("profile %q is not available on the host agent (only %q; the WAF set is wafio-waf-agent fetch-data)", p, hostFetchProfileName)
	}
	for _, s := range strings.Split(hostFetchOnly, ",") {
		if t := strings.ToLower(strings.TrimSpace(s)); t != "" && t != hostFetchComponent && t != "geoip" {
			return fmt.Errorf("component %q is not available on the host agent (only %s)", t, hostFetchComponent)
		}
	}

	fmt.Println("WAFio Host Agent — Security Data Fetcher")
	fmt.Println(strings.Repeat("─", 52))

	mmKey := hostFetchMaxMindKey
	if mmKey == "" {
		mmKey = os.Getenv("WAFIO_MAXMIND_LICENSE_KEY")
	}

	if mmKey != "" {
		fmt.Println("  GeoIP provider : MaxMind GeoLite2")
	} else {
		fmt.Println("  GeoIP provider : DB-IP (free, no key)")
	}
	fmt.Printf("  Output dir     : %s\n", hostFetchDir)
	if hostFetchOnly == "" {
		fmt.Printf("  Profile        : %s → %s\n", hostFetchProfileName, hostFetchComponent)
	}
	fmt.Println()

	opts := geo.FetchOptions{
		Dir:               hostFetchDir,
		MaxMindLicenseKey: mmKey,
		Force:             hostFetchForce,
		Log: func(format string, args ...any) {
			fmt.Printf(format+"\n", args...)
		},
	}

	start := time.Now()
	results := geo.FetchDatabases(context.Background(), opts, true, false, false)

	fmt.Printf("\n%s\n", strings.Repeat("─", 52))

	failed := 0
	for _, r := range results {
		if r.Err != nil {
			failed++
		}
	}

	elapsed := time.Since(start).Round(time.Millisecond)
	if failed == 0 {
		fmt.Printf("✅  All security data ready (%v)\n\n", elapsed)
		printHostAgentStartHint(hostFetchDir)
	} else {
		fmt.Printf("⚠️   Completed with %d error(s) (%v)\n", failed, elapsed)
		for _, r := range results {
			if r.Err != nil {
				fmt.Fprintf(os.Stderr, "  ERROR [%s]: %v\n", r.Component, r.Err)
			}
		}
		return fmt.Errorf("%d component(s) failed", failed)
	}
	return nil
}

func printHostAgentStartHint(dir string) {
	fmt.Println("Host agent startup flag for this machine:")
	fmt.Printf("  --geoip-db  %s/geoip/country.mmdb\n", dir)
}
