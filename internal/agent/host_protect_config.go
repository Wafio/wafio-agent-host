package agent

import (
	"fmt"
	"strconv"
	"strings"

	wafebpf "github.com/wafio/wafio-agent-host/internal/ebpf"
)

// Environment variables for the host agent's protected-process settings.
// Each is read only when its command-line flag was not given, the same
// flag-then-env order as the other WAFIO_* host agent settings; systemd units
// supply them through /etc/wafio/host-agent.env.
const (
	// EnvProtectedProcesses: comma-separated executable basenames, added to
	// the built-in protected names.
	EnvProtectedProcesses = "WAFIO_PROTECTED_PROCESSES"
	// EnvProtectedExePaths: comma-separated absolute executable paths.
	EnvProtectedExePaths = "WAFIO_PROTECTED_EXE_PATHS"
	// EnvProtectedReplaceDefaults: boolean; true drops the built-in names so
	// only the configured entries apply.
	EnvProtectedReplaceDefaults = "WAFIO_PROTECTED_REPLACE_DEFAULTS"
)

// EnvEBPFMapScale is the environment fallback of --ebpf-map-scale: "auto"
// (the default) or a number above 0 and at most 1. It is read only when the
// flag was not given, like the protected-process settings above.
const EnvEBPFMapScale = "WAFIO_EBPF_MAP_SCALE"

// LoadMapScale resolves the eBPF map scale: the flag when it was given, else
// the environment. An invalid value stops the agent at startup.
func (c *HostConfig) LoadMapScale(getenv func(string) string, flagSet bool) error {
	if !flagSet {
		if v := strings.TrimSpace(getenv(EnvEBPFMapScale)); v != "" {
			c.EBPFMapScale = v
		}
	}
	if _, _, err := wafebpf.ParseMapScale(c.EBPFMapScale); err != nil {
		return fmt.Errorf("invalid --ebpf-map-scale %q (or %s): %w", c.EBPFMapScale, EnvEBPFMapScale, err)
	}
	return nil
}

// ProtectedFlagsSet records which protected-process settings were given on
// the command line. Those win over the environment.
type ProtectedFlagsSet struct {
	Names           bool
	ExePaths        bool
	ReplaceDefaults bool
}

// ProtectedProcessConfig returns the protected-process part of cfg.
func (c HostConfig) ProtectedProcessConfig() wafebpf.ProtectedProcessConfig {
	return wafebpf.ProtectedProcessConfig{
		Names:           c.ProtectedProcessNames,
		ExePaths:        c.ProtectedExePaths,
		ReplaceDefaults: c.ProtectedReplaceDefaults,
	}
}

// LoadProtectedProcesses resolves the protected-process settings: values set
// by a flag are trimmed and kept; every other setting falls back to its
// environment variable when that is non-blank. The result is validated, so a
// malformed entry stops the agent at startup instead of being dropped
// silently. Built-in names are always kept unless replace-defaults is set.
func (c *HostConfig) LoadProtectedProcesses(getenv func(string) string, set ProtectedFlagsSet) error {
	if set.Names {
		c.ProtectedProcessNames = trimProtectedList(c.ProtectedProcessNames)
	} else if v := getenv(EnvProtectedProcesses); strings.TrimSpace(v) != "" {
		c.ProtectedProcessNames = wafebpf.SplitProtectedList(v)
	}
	if set.ExePaths {
		c.ProtectedExePaths = trimProtectedList(c.ProtectedExePaths)
	} else if v := getenv(EnvProtectedExePaths); strings.TrimSpace(v) != "" {
		c.ProtectedExePaths = wafebpf.SplitProtectedList(v)
	}
	if !set.ReplaceDefaults {
		if v := strings.TrimSpace(getenv(EnvProtectedReplaceDefaults)); v != "" {
			b, err := strconv.ParseBool(v)
			if err != nil {
				return fmt.Errorf("%s: invalid boolean %q", EnvProtectedReplaceDefaults, v)
			}
			c.ProtectedReplaceDefaults = b
		}
	}
	return c.ProtectedProcessConfig().Validate()
}

// trimProtectedList trims the items of a flag-supplied list (pflag splits
// "a, b" into "a" and " b"). Empty items stay for Validate to report.
func trimProtectedList(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.TrimSpace(s)
	}
	return out
}
