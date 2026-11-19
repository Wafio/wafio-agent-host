package ebpf

import (
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"unicode"
)

// ────────────────────────────────────────────────────────────────────────────
//  Protected-process configuration
//
//  Operators extend the protected set with their own daemons (host agent
//  --protected-processes / WAFIO_PROTECTED_PROCESSES and
//  --protected-exe-paths / WAFIO_PROTECTED_EXE_PATHS). Configured names are
//  ADDED to DefaultProtectedProcessNames; the built-in names are dropped only
//  when ReplaceDefaults is set explicitly.
// ────────────────────────────────────────────────────────────────────────────

const (
	// maxProtectedNameLen is NAME_MAX: no executable basename is longer.
	maxProtectedNameLen = 255
	// maxProtectedExePathLen is PATH_MAX minus the terminating NUL.
	maxProtectedExePathLen = 4095
	// maxProtectedEntries bounds each configured list. The kernel map holds
	// maxProtectedTGIDs processes; a longer configuration is a mistake.
	maxProtectedEntries = 256
)

// ProtectedProcessConfig is the operator-supplied part of the protected set.
type ProtectedProcessConfig struct {
	// Names are executable basenames. A name protects a root process whose
	// binary is that host file in a system directory (see matchIdentity).
	Names []string
	// ExePaths are exact absolute executable paths. They protect that host
	// binary whatever user it runs as.
	ExePaths []string
	// ReplaceDefaults drops DefaultProtectedProcessNames and
	// DefaultProtectedUnitExes so only Names and ExePaths apply. A built-in
	// unit path listed again in ExePaths keeps its unit requirement. Honored only
	// when at least one valid entry remains.
	ReplaceDefaults bool
}

// SplitProtectedList splits a comma-separated configuration value. A blank
// value is no entries; items are trimmed, and an empty item ("a,,b") is kept
// so Validate reports it instead of silently dropping it.
func SplitProtectedList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	for i, p := range parts {
		parts[i] = strings.TrimSpace(p)
	}
	return parts
}

// Validate reports every invalid entry: empty items, names that are paths or
// traversal components, exe paths that are relative, contain "..", or are not
// in canonical form. ReplaceDefaults with nothing to replace them with is an
// error too, because it would leave only pid<=1 and the agent protected.
func (c ProtectedProcessConfig) Validate() error {
	var errs []error
	if len(c.Names) > maxProtectedEntries {
		errs = append(errs, fmt.Errorf("protected process names: %d entries, at most %d allowed", len(c.Names), maxProtectedEntries))
	}
	if len(c.ExePaths) > maxProtectedEntries {
		errs = append(errs, fmt.Errorf("protected exe paths: %d entries, at most %d allowed", len(c.ExePaths), maxProtectedEntries))
	}
	for i, n := range c.Names {
		if err := validateProtectedName(n); err != nil {
			errs = append(errs, fmt.Errorf("protected process name #%d: %w", i+1, err))
		}
	}
	for i, p := range c.ExePaths {
		if err := validateProtectedExePath(p); err != nil {
			errs = append(errs, fmt.Errorf("protected exe path #%d: %w", i+1, err))
		}
	}
	if c.ReplaceDefaults && len(c.Names) == 0 && len(c.ExePaths) == 0 {
		errs = append(errs, errors.New("replace defaults requested but no protected process names or exe paths configured; the built-in list would be removed with nothing in its place"))
	}
	return errors.Join(errs...)
}

// validateProtectedName checks one executable basename.
func validateProtectedName(raw string) error {
	n := strings.TrimSpace(raw)
	switch {
	case n == "":
		return errors.New("empty entry")
	case len(n) > maxProtectedNameLen:
		return fmt.Errorf("%.32q...: longer than %d bytes", n, maxProtectedNameLen)
	case n == "." || n == "..":
		return fmt.Errorf("%q: path traversal component, not an executable name", n)
	case strings.ContainsAny(n, `/\`):
		return fmt.Errorf("%q: must be an executable basename, not a path (use the exe paths setting for exact paths)", n)
	case hasControlChar(n):
		return fmt.Errorf("%q: contains control characters", n)
	}
	return nil
}

// validateProtectedExePath checks one exact executable path. The path is
// matched against /proc/<pid>/exe, which the kernel always reports absolute
// and canonical, so anything else could never match (or, for "..", could be
// read as pointing somewhere it does not).
func validateProtectedExePath(raw string) error {
	p := strings.TrimSpace(raw)
	switch {
	case p == "":
		return errors.New("empty entry")
	case len(p) > maxProtectedExePathLen:
		return fmt.Errorf("%.32q...: longer than %d bytes", p, maxProtectedExePathLen)
	case hasControlChar(p):
		return fmt.Errorf("%q: contains control characters", p)
	case !strings.HasPrefix(p, "/"):
		return fmt.Errorf("%q: must be an absolute path", p)
	case slices.Contains(strings.Split(p, "/"), ".."):
		return fmt.Errorf("%q: path traversal (\"..\") not allowed", p)
	case p == "/" || strings.HasSuffix(p, "/"):
		return fmt.Errorf("%q: must name an executable file, not a directory", p)
	case filepath.Clean(p) != p:
		return fmt.Errorf("%q: not in canonical form (use %q)", p, filepath.Clean(p))
	}
	return nil
}

func hasControlChar(s string) bool {
	return strings.ContainsFunc(s, unicode.IsControl)
}

// validNames returns the valid configured names, trimmed and de-duplicated.
func (c ProtectedProcessConfig) validNames() []string {
	var out []string
	for _, n := range c.Names {
		if validateProtectedName(n) == nil {
			out = append(out, strings.TrimSpace(n))
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// validExePaths returns the valid configured exe paths, sorted and
// de-duplicated.
func (c ProtectedProcessConfig) validExePaths() []string {
	var out []string
	for _, p := range c.ExePaths {
		if validateProtectedExePath(p) == nil {
			out = append(out, strings.TrimSpace(p))
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// defaultsReplaced reports whether the built-in names are dropped: only when
// requested AND a valid entry remains, so a configuration whose every entry
// is invalid can never empty the protected set.
func (c ProtectedProcessConfig) defaultsReplaced() bool {
	return c.ReplaceDefaults && (len(c.validNames()) > 0 || len(c.validExePaths()) > 0)
}

// EffectiveNames is the sorted, de-duplicated list of protected executable
// basenames: DefaultProtectedProcessNames plus the valid configured names, or
// only the configured names when the defaults are replaced. Invalid entries
// are skipped (Validate reports them).
func (c ProtectedProcessConfig) EffectiveNames() []string {
	names := c.validNames()
	if !c.defaultsReplaced() {
		names = append(names, DefaultProtectedProcessNames...)
	}
	slices.Sort(names)
	return slices.Compact(names)
}

// EffectiveExePaths is the sorted, de-duplicated list of protected exact
// executable paths: the valid configured ones plus the built-in unit
// executables (DefaultProtectedUnitExes), unless the defaults are replaced.
func (c ProtectedProcessConfig) EffectiveExePaths() []string {
	paths := c.validExePaths()
	if !c.defaultsReplaced() {
		paths = slices.AppendSeq(paths, maps.Keys(DefaultProtectedUnitExes))
	}
	slices.Sort(paths)
	return slices.Compact(paths)
}

// NewProtectedProcessSetFromConfig builds the protected set from cfg. Invalid
// entries are dropped; callers run Validate first to report them.
func NewProtectedProcessSetFromConfig(cfg ProtectedProcessConfig) *ProtectedProcessSet {
	s := &ProtectedProcessSet{
		names:            make(map[string]struct{}),
		comms:            make(map[string]struct{}),
		exes:             make(map[string]struct{}),
		units:            make(map[string]string),
		defaultsReplaced: cfg.defaultsReplaced(),
	}
	// The unit requirement follows the path, so an operator who replaces the
	// defaults and lists a built-in path again still gets the unit check.
	maps.Copy(s.units, DefaultProtectedUnitExes)
	for _, n := range cfg.EffectiveNames() {
		s.names[n] = struct{}{}
		s.comms[truncateComm(n)] = struct{}{}
	}
	for _, p := range cfg.EffectiveExePaths() {
		s.exes[p] = struct{}{}
		s.comms[truncateComm(filepath.Base(p))] = struct{}{}
	}
	return s
}

// Names returns the protected executable basenames, sorted.
func (s *ProtectedProcessSet) Names() []string {
	if s == nil {
		return nil
	}
	return sortedKeys(s.names)
}

// ExePaths returns the protected exact executable paths, sorted.
func (s *ProtectedProcessSet) ExePaths() []string {
	if s == nil {
		return nil
	}
	return sortedKeys(s.exes)
}

// unitExePaths returns the executable paths bound to a unit, sorted.
func (s *ProtectedProcessSet) unitExePaths() []string {
	if s == nil {
		return nil
	}
	paths := make([]string, 0, len(s.units))
	for p := range s.units {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	return paths
}

// riskyProtectedNames are shells, interpreters and multi-call binaries.
// Protecting one exempts every root process running that host binary from
// Kill enforcement — which is what a post-exploitation shell or one-liner
// runs as. Not rejected (an operator may have a reason), but warned about at
// startup and on the self-check line.
var riskyProtectedNames = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ash": true, "ksh": true,
	"mksh": true, "csh": true, "tcsh": true, "fish": true,
	"busybox": true, "toybox": true, "env": true, "sudo": true, "su": true, "doas": true,
	"node": true, "nodejs": true, "deno": true, "bun": true, "luajit": true,
	"socat": true, "nc": true, "ncat": true, "netcat": true,
}

// riskyProtectedPrefixes are interpreter families whose basenames carry a
// version suffix (python3, python3.12, perl5.36, php8.2, ruby3.1, lua5.4).
var riskyProtectedPrefixes = []string{"python", "perl", "ruby", "php", "lua"}

// isRiskyProtectedName reports whether basename names a shell, interpreter or
// multi-call binary.
func isRiskyProtectedName(basename string) bool {
	n := strings.ToLower(basename)
	if riskyProtectedNames[n] {
		return true
	}
	for _, p := range riskyProtectedPrefixes {
		if rest, ok := strings.CutPrefix(n, p); ok && strings.Trim(rest, "0123456789.") == "" {
			return true
		}
	}
	return false
}

// RiskyEntries returns the protected names and exe paths that name a shell,
// interpreter or multi-call binary, sorted. The built-in names never do.
func (s *ProtectedProcessSet) RiskyEntries() []string {
	if s == nil {
		return nil
	}
	var out []string
	for n := range s.names {
		if isRiskyProtectedName(n) {
			out = append(out, n)
		}
	}
	for p := range s.exes {
		if isRiskyProtectedName(filepath.Base(p)) {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return out
}

// RiskyWarning is the startup warning for RiskyEntries, or "" when none.
func (s *ProtectedProcessSet) RiskyWarning() string {
	risky := s.RiskyEntries()
	if len(risky) == 0 {
		return ""
	}
	return fmt.Sprintf("WARNING protected-process set includes shells/interpreters [%s]: every root process running them is exempt from Kill enforcement; protect the daemon's own binary path instead",
		strings.Join(risky, ","))
}

// Summary is the one-line effective configuration for the startup log.
func (s *ProtectedProcessSet) Summary() string {
	defaults := "merged"
	if s != nil && s.defaultsReplaced {
		defaults = "replaced"
	}
	return fmt.Sprintf("names=[%s] exe_paths=[%s] builtin_defaults=%s",
		strings.Join(s.Names(), ","), strings.Join(s.ExePaths(), ","), defaults)
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// ────────────────────────────────────────────────────────────────────────────
//  Startup self-check
// ────────────────────────────────────────────────────────────────────────────

// protectedSelfCheckPrefix starts the startup self-check log line; deploy
// verification greps for it.
const protectedSelfCheckPrefix = "protected-process self-check:"

// protectedSelfCheck is the state reported once at trace start: whether the
// loaded object carries the kernel protected set and how many processes it
// protects.
type protectedSelfCheck struct {
	kernelSet   bool     // trace_protected_tgids present in the loaded object
	valueSize   uint32   // 8 = start-time ABI, 1 = legacy presence flag
	kernelTGIDs int      // entries written to the kernel map
	matched     int      // processes in /proc the protected set matched
	scanErr     error    // /proc scan failure, if any
	risky       []string // protected shells/interpreters (RiskyEntries)
	// procDenied: the identity links of root daemons are unreadable
	// (procIdentityDenied), so nothing beyond pid<=1 and the agent is protected.
	procDenied bool
	// untrusted: paths an account other than root can write, under protected
	// processes that are therefore not protected (scanProtectedTGIDs).
	untrusted []string
	// unitUnavailable: the executable paths bound to a unit when the unit of a
	// process cannot be told (unitCheckAvailable): none of them is protected.
	unitUnavailable []string
}

// protectedUnitCheckHint names the fix on the self-check line and in the
// startup warning.
const protectedUnitCheckHint = "the agent runs in a cgroup namespace of its own and PID 1's root shows no readable system.slice: run it in the host cgroup namespace"

// protectedUntrustedHint names the fix on the log line and in the startup
// warning.
const protectedUntrustedHint = "make root the owner and remove group and other write"

// protectedUntrustedDeletedHint replaces it for a path that ends in " (deleted)":
// the file the process runs is gone from disk, so no chown or chmod reaches it.
const protectedUntrustedDeletedHint = "find out how a file that an account other than root could write ran at this path, fix its directory and restart the process"

// untrustedHint is the fix for one path of the untrusted list.
func untrustedHint(path string) string {
	if strings.HasSuffix(path, " (deleted)") {
		return protectedUntrustedDeletedHint
	}
	return protectedUntrustedHint
}

// protectedProcDeniedHint names the fix on the self-check line and in the
// startup warning.
const protectedProcDeniedHint = "grant CAP_SYS_PTRACE (AmbientCapabilities and CapabilityBoundingSet): /proc/<pid>/exe of root daemons is unreadable, so only pid 1 and the agent are protected from Kill"

// String renders the self-check as one grep-friendly line of key=value pairs.
func (c protectedSelfCheck) String() string {
	var b strings.Builder
	b.WriteString(protectedSelfCheckPrefix)
	if c.kernelSet {
		abi := "start_ticks"
		if c.valueSize != 8 {
			abi = "presence_flag"
		}
		fmt.Fprintf(&b, " kernel_set=present map=%s value=%s protected_tgids=%d", traceProtectedMapName, abi, c.kernelTGIDs)
	} else {
		fmt.Fprintf(&b, " kernel_set=absent map=%s protected_tgids=0", traceProtectedMapName)
	}
	guard := "on"
	if c.procDenied {
		guard = "degraded proc_access=denied"
	}
	fmt.Fprintf(&b, " matched_processes=%d userspace_guard=%s", c.matched, guard)
	if c.matched > c.kernelTGIDs && c.kernelSet && c.scanErr == nil {
		fmt.Fprintf(&b, " kernel_missing=%d", c.matched-c.kernelTGIDs)
	}
	if c.scanErr != nil {
		fmt.Fprintf(&b, " scan_error=%q", c.scanErr.Error())
	}
	if len(c.risky) > 0 {
		fmt.Fprintf(&b, " warning=risky_protected:%s", strings.Join(c.risky, ","))
	}
	if len(c.untrusted) > 0 {
		fmt.Fprintf(&b, " untrusted_owner=%s", strings.Join(c.untrusted, ","))
	}
	if len(c.unitUnavailable) > 0 {
		fmt.Fprintf(&b, " unit_check=unavailable hint=%q", protectedUnitCheckHint)
	}
	if !c.kernelSet {
		b.WriteString(" note=\"trace object predates the protected set; kernel kill paths skip only pid<=1 and the agent\"")
	}
	if c.procDenied {
		fmt.Fprintf(&b, " hint=%q", protectedProcDeniedHint)
	}
	return b.String()
}

// Warning is the separate startup warning for a self-check that found the
// protected set unenforceable, one line for each cause; "" when there is none.
func (c protectedSelfCheck) Warning() string {
	var lines []string
	if c.procDenied {
		lines = append(lines, "WARNING: protected-process identity check denied: "+protectedProcDeniedHint)
	}
	var live, replaced []string
	for _, p := range c.untrusted {
		if untrustedHint(p) == protectedUntrustedHint {
			live = append(live, p)
		} else {
			replaced = append(replaced, p)
		}
	}
	for _, paths := range [][]string{live, replaced} {
		if len(paths) > 0 {
			lines = append(lines, "WARNING: protected processes without protection, an account other than root can write "+strings.Join(paths, ", ")+": "+untrustedHint(paths[0]))
		}
	}
	if len(c.unitUnavailable) > 0 {
		lines = append(lines, "WARNING: protected-process unit check unavailable, not protected: "+strings.Join(c.unitUnavailable, ", ")+": "+protectedUnitCheckHint)
	}
	return strings.Join(lines, "\n")
}

// traceProtectedMapName mirrors the trace object's protected-set map name for
// platform-independent code (trace_manager.go's traceMapProtected is Linux-only).
const traceProtectedMapName = "trace_protected_tgids"
