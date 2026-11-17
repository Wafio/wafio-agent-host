// Command wafio-host-agent — host-scoped eBPF kernel firewall + runtime
// tracing agent. This binary does NOT perform L7 WAF analysis; pair it with
// wafio-waf-agent if you need HTTP inspection on the same host.
//
// Privileges: requires CAP_BPF and CAP_NET_ADMIN. Run as root or with the
// appropriate capabilities set on the binary.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
	"github.com/spf13/cobra"
	"github.com/wafio/wafio-agent-host/internal/agent"
	wafebpf "github.com/wafio/wafio-agent-host/internal/ebpf"
	"github.com/wafio/wafio-cp-backend/shared/agentcore"
	"github.com/wafio/wafio-cp-backend/shared/metrics"
)

var cfg = agent.DefaultHostConfig()

const (
	flagProtectedProcesses       = "protected-processes"
	flagProtectedExePaths        = "protected-exe-paths"
	flagProtectedReplaceDefaults = "protected-replace-defaults"
)

var rootCmd = &cobra.Command{
	Use:   "wafio-host-agent",
	Short: "Host-scoped eBPF firewall + runtime tracing agent",
	Long: `wafio-host-agent attaches XDP/TC programs to a network interface to perform
kernel-level L3/L4 firewalling (block-list, allow-list, geo-block, rate limit,
SYN-flood mitigation) and/or runtime security tracing (syscall monitoring,
process attestation).

Exactly one instance should run per host/VM/K8s-node. It streams telemetry to
a WAFio control plane over gRPC with mutual TLS (--grpc-server, --grpc-client-cert,
--grpc-client-key and --grpc-ca-cert). Without a complete gRPC setup, or when
the stream cannot start, it falls back to HTTP push to --server-url,
authenticated by --host-key.

For HTTP/WAF inspection, deploy wafio-waf-agent alongside this binary.`,
	RunE: run,
}

func init() {
	// eBPF firewall (XDP/TC).
	rootCmd.Flags().BoolVar(&cfg.EBPFEnabled, "ebpf", true, "enable eBPF kernel-level firewall (requires CAP_BPF)")
	rootCmd.Flags().StringVar(&cfg.EBPFInterface, "interface", "eth0", "network interface for XDP/TC attachment")
	rootCmd.Flags().StringVar(&cfg.EBPFXDPObject, "xdp-obj", "internal/ebpf/bpf/wafio_xdp.o", "path to compiled XDP BPF object")
	rootCmd.Flags().StringVar(&cfg.EBPFTCObject, "tc-obj", "internal/ebpf/bpf/wafio_tc.o", "path to compiled TC BPF object")
	rootCmd.Flags().StringVar(&cfg.EBPFPinPath, "pin-path", "/sys/fs/bpf/wafio", "bpffs pin path for eBPF maps")
	rootCmd.Flags().StringVar(&cfg.EBPFXDPMode, "xdp-mode", "auto", "XDP attach mode: auto|skb|driver|hw")

	// eBPF runtime security tracing.
	rootCmd.Flags().BoolVar(&cfg.TraceEnabled, "trace", false, "enable eBPF runtime security tracing")
	rootCmd.Flags().StringVar(&cfg.TraceObjectPath, "trace-obj", "internal/ebpf/bpf/wafio_trace.o", "path to compiled trace BPF object")
	rootCmd.Flags().BoolVar(&cfg.LSMEnabled, "lsm", true, "enable BPF-LSM proactive blocking (requires kernel BPF-LSM hooks)")
	rootCmd.Flags().BoolVar(&cfg.LSMBlockConnect, "lsm-block-connect", false, "LSM: deny socket_connect, and addressed sends (sendto, MSG_FASTOPEN), to blocklisted IPs (-EPERM)")

	// Protected processes: never killed by runtime-security Kill enforcement.
	// Added to the built-in names unless --protected-replace-defaults is set.
	rootCmd.Flags().StringSliceVar(&cfg.ProtectedProcessNames, flagProtectedProcesses, nil,
		"extra executable basenames never killed by enforcement, comma-separated; added to the built-in "+
			strings.Join(wafebpf.DefaultProtectedProcessNames, ",")+" (env "+agent.EnvProtectedProcesses+")")
	rootCmd.Flags().StringSliceVar(&cfg.ProtectedExePaths, flagProtectedExePaths, nil,
		"absolute executable paths never killed by enforcement, comma-separated (env "+agent.EnvProtectedExePaths+")")
	rootCmd.Flags().BoolVar(&cfg.ProtectedReplaceDefaults, flagProtectedReplaceDefaults, false,
		"replace the built-in protected names instead of extending them (env "+agent.EnvProtectedReplaceDefaults+")")

	// Local control/callback listener. Only used for ops callbacks from the
	// control plane (block-ip, reload, etc.) — NOT for HTTP analysis.
	rootCmd.Flags().StringVar(&cfg.ListenAddr, "listen", "127.0.0.1:18089", "local control/callback HTTP listen address")
	// Local API token: generated each start, required as Bearer on
	// every local route except /healthz.
	rootCmd.Flags().StringVar(&cfg.LocalAPITokenFile, "local-api-token-file", "",
		"where the per-start local API token is written (default "+agentcore.DefaultLocalAPITokenFile+"; env "+agentcore.EnvLocalAPITokenFile+")")
	rootCmd.Flags().StringVar(&cfg.LocalAPITokenGroup, "local-api-token-group", "",
		"group allowed to read the token file (mode 0640 instead of 0600), e.g. the WAF agent's service group for IP-jail pushes (env "+agentcore.EnvLocalAPITokenGroup+")")

	// Control plane identity and the HTTP fallback transport.
	rootCmd.Flags().StringVar(&cfg.ServerURL, "server-url", "", "WAFio control plane base URL (e.g. https://wafio.example.com) for the HTTP telemetry fallback; used only when the gRPC stream is not configured or cannot start, and needs --host-key")
	rootCmd.Flags().StringVar(&cfg.HostKey, "host-key", "", "WAFio Host Key (wafh_...) issued in the web panel; identifies the host on the gRPC stream and in HTTP fallback pushes")
	rootCmd.Flags().StringVar(&cfg.AgentAPIKey, "agent-api-key", "", "DEPRECATED: the control plane ignores it and accepts only --host-key; kept so old unit files still start, but with no host key and no gRPC stream the agent refuses to start")
	rootCmd.Flags().StringVar(&cfg.AgentName, "agent-name", "", "friendly process name shown in the control plane (defaults to hostname)")

	// GeoIP enrichment.
	rootCmd.Flags().StringVar(&cfg.GeoIPDBPath, "geoip-db", "", "path to MaxMind GeoLite2-Country.mmdb (enables geo-blocking)")

	// gRPC stream transport (preferred over HTTP push for new deployments).
	rootCmd.Flags().StringVar(&cfg.GRPCServer, "grpc-server", "", "control plane gRPC address (host:port, e.g. wafio.example.com:9090)")
	rootCmd.Flags().StringVar(&cfg.GRPCServerName, "grpc-server-name", "", "SNI override for gRPC TLS verification (defaults to grpc-server hostname)")
	rootCmd.Flags().StringVar(&cfg.GRPCClientCert, "grpc-client-cert", "", "mTLS client cert PEM file (e.g. /etc/wafio/agent/client.crt)")
	rootCmd.Flags().StringVar(&cfg.GRPCClientKey, "grpc-client-key", "", "mTLS client key PEM file  (e.g. /etc/wafio/agent/client.key)")
	rootCmd.Flags().StringVar(&cfg.GRPCCACert, "grpc-ca-cert", "", "mTLS CA cert PEM file     (e.g. /etc/wafio/agent/ca.crt)")
}

func run(cmd *cobra.Command, _ []string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("wafio-host-agent requires Linux (eBPF XDP/TC); current OS=%s", runtime.GOOS)
	}

	// Kernels before 5.11 charge BPF maps to RLIMIT_MEMLOCK, and a map create
	// fails with EPERM once the limit is used up. The unit sets
	// LimitMEMLOCK=infinity; raising it here too covers a start without it.
	// A failure is not fatal: newer kernels do not need it.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("[wafio-host-agent] WARN: remove memlock rlimit: %v (relying on LimitMEMLOCK)", err)
	}

	// Env-var fallbacks so systemd units can inject secrets without exposing
	// them on the command line (where they would show up in `ps`).
	if cfg.HostKey == "" {
		cfg.HostKey = os.Getenv("WAFIO_HOST_KEY")
	}
	if cfg.AgentAPIKey == "" {
		cfg.AgentAPIKey = os.Getenv("WAFIO_AGENT_API_KEY")
	}
	if cfg.ServerURL == "" {
		cfg.ServerURL = os.Getenv("WAFIO_SERVER_URL")
	}
	if cfg.AgentName == "" {
		cfg.AgentName = os.Getenv("WAFIO_AGENT_NAME")
	}
	// gRPC stream env fallbacks.
	if cfg.GRPCServer == "" {
		cfg.GRPCServer = os.Getenv("WAFIO_GRPC_SERVER")
	}
	if cfg.GRPCServerName == "" {
		cfg.GRPCServerName = os.Getenv("WAFIO_GRPC_SERVER_NAME")
	}
	if cfg.GRPCClientCert == "" {
		cfg.GRPCClientCert = os.Getenv("WAFIO_GRPC_CLIENT_CERT")
	}
	if cfg.GRPCClientKey == "" {
		cfg.GRPCClientKey = os.Getenv("WAFIO_GRPC_CLIENT_KEY")
	}
	if cfg.GRPCCACert == "" {
		cfg.GRPCCACert = os.Getenv("WAFIO_GRPC_CA_CERT")
	}
	if cfg.LocalAPITokenFile == "" {
		cfg.LocalAPITokenFile = os.Getenv(agentcore.EnvLocalAPITokenFile)
	}
	if cfg.LocalAPITokenFile == "" {
		cfg.LocalAPITokenFile = agentcore.DefaultLocalAPITokenFile
	}
	if cfg.LocalAPITokenGroup == "" {
		cfg.LocalAPITokenGroup = os.Getenv(agentcore.EnvLocalAPITokenGroup)
	}
	flags := cmd.Flags()
	if err := cfg.LoadProtectedProcesses(os.Getenv, agent.ProtectedFlagsSet{
		Names:           flags.Changed(flagProtectedProcesses),
		ExePaths:        flags.Changed(flagProtectedExePaths),
		ReplaceDefaults: flags.Changed(flagProtectedReplaceDefaults),
	}); err != nil {
		return fmt.Errorf("invalid protected-process configuration: %w", err)
	}
	if !cfg.EBPFEnabled && !cfg.TraceEnabled {
		return fmt.Errorf("neither --ebpf nor --trace is enabled; nothing to do")
	}

	// Register explicit component paths so the control plane receives accurate
	// install locations — same pattern as WAF agent. Explicit path wins over
	// secDataDir derivation. secDataDir is still set as fallback for any
	// component not explicitly configured.
	if cfg.GeoIPDBPath != "" {
		agent.SetEBPFComponentPaths(map[string]string{
			"geoip-country": cfg.GeoIPDBPath,
		})
		// Derive secDataDir (parent of geoip/) as fallback base for future components.
		agent.SetEBPFSecurityDataDir(filepath.Dir(filepath.Dir(cfg.GeoIPDBPath)))
	}

	// OpenMetrics listener: loopback only.
	if addr := os.Getenv(metrics.EnvAddr); addr != "" {
		reg := metrics.NewRegistry()
		agent.RegisterHostMetrics(reg)
		ln, err := metrics.Listen(addr, nil)
		if err != nil {
			return err
		}
		defer metrics.Serve(ln, reg, log.Printf)()
		log.Printf("[wafio-host-agent] metrics listening on %s/metrics", ln.Addr())
	}

	runCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return agent.RunHost(runCtx, cfg)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
