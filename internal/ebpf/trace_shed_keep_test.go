package ebpf

import (
	"path/filepath"
	"strings"
	"testing"
)

// keptUnderPressure mirrors trace_open_keep for a name
// set (the C side is TestTraceShedKeepsRaisableEvents): non-canonical
// absolute path, relative write, or a listed component.
func keptUnderPressure(keys map[uint64]uint8, path string, flags uint32) bool {
	modifies := flags&3 != 0 || flags&0o1000 != 0
	if strings.HasPrefix(path, "/") {
		if path != "/" && filepath.Clean(path) != path {
			return true
		}
	} else if modifies {
		return true
	}
	comps := strings.Split(path, "/")
	for i, c := range comps {
		if c == "" {
			continue
		}
		v, ok := keys[traceNameHash(c)]
		if !ok {
			continue
		}
		final := i == len(comps)-1
		if modifies || v&traceKeepDir != 0 || (final && v&traceKeepName != 0) {
			return true
		}
	}
	return false
}

// The kernel must not shed an openat that ingest or the agent
// raises after the ring. The built-in names cover the classification tiers
// that reach MEDIUM (filePathTier: credential, auth and persistence for any
// access, network config for a write) and the agent's own raises; ordinary
// reads (network config reads, done on every DNS lookup, and public identity
// reads, which ingest drops) stay sheddable.
func TestShedKeepNamesBuiltin(t *testing.T) {
	keys := traceKeepNameKeys(shedKeepNames(nil))
	const rd, wr = 0, 1
	kept := []struct {
		path  string
		flags uint32
	}{
		{"/etc/shadow", rd}, {"/etc/gshadow", rd}, {"/root/.ssh/id_rsa", rd}, {"/home/u/.ssh/id_ed25519", rd},
		{"/etc/ssh/ssh_host_ed25519_key", rd}, {"/etc/ssl/private/site.key", rd}, {"/etc/letsencrypt/live/x/privkey.pem", rd},
		{"/home/u/.aws/credentials", rd}, {"/home/u/.docker/config.json", rd}, {"/home/u/.gnupg/secring.gpg", rd},
		{"/proc/1234/mem", rd}, {"/proc/1234/environ", rd},
		{"/etc/passwd", wr}, {"/etc/group", wr}, {"/etc/nsswitch.conf", wr}, {"/root/.ssh/authorized_keys", wr},
		{"/etc/sudoers", rd}, {"/etc/sudoers.d/90-cloud", rd},
		{"/etc/pam.d/sshd", rd}, {"/etc/security/limits.conf", rd},
		{"/etc/crontab", rd}, {"/etc/cron.d/job", rd}, {"/var/spool/cron/crontabs/root", rd}, {"/etc/profile.d/x.sh", rd},
		{"/etc/init.d/svc", rd}, {"/etc/rc.local", rd}, {"/home/u/.bashrc", rd}, {"/etc/ld.so.conf.d/x.conf", rd},
		{"/etc/systemd/system/evil.service", wr}, {"/etc/hosts", wr}, {"/etc/resolv.conf", wr}, {"/etc/netplan/01.yaml", wr},
		{"/etc//shadow", rd}, {"/tmp/../etc/sudoers.d/x", wr}, {"x", wr}, {"shadow", rd}, {"../sudoers.d/y", rd},
	}
	for _, k := range kept {
		if !keptUnderPressure(keys, k.path, k.flags) {
			t.Errorf("%s (flags %d) would be shed", k.path, k.flags)
		}
	}
	// Reads of the public identity files are what ingest lowers to
	// INFO and drops (isPublicIdentityRead); exempting them let a read loop
	// of /etc/passwd fill the ring past shedding.
	shed := []string{"/etc/passwd", "/etc/group", "/etc/nsswitch.conf", "/root/.ssh/authorized_keys",
		"/etc/hosts", "/etc/resolv.conf", "/etc/systemd/system/x.service", "/sys/devices/system/cpu/online",
		"/usr/lib/x86_64-linux-gnu/libc.so.6", "/proc/self/stat", "/home/u/.ssh/known_hosts", "/tmp/build/a.o", "x", "./x"}
	for _, p := range shed {
		if keptUnderPressure(keys, p, rd) {
			t.Errorf("%s read would be kept", p)
		}
	}
	if len(keys) > 512 {
		t.Fatalf("%d built-in names leave too little of trace_keep_names (1024) for policies", len(keys))
	}
}

// Alert, Simulate and Kill policies act on the exported event in userspace:
// their filename terms are never shed (a directory term for any file below).
func TestShedKeepNamesFromPolicies(t *testing.T) {
	got := shedKeepNames(policySet(
		EnforcementPolicy{Enabled: true, Action: "alert", MatchFilename: "/opt/app/Secret.key, /srv/vault/"},
		EnforcementPolicy{Enabled: true, Action: "simulate", EventTypes: []string{"openat"}, MatchFilename: "/data/x.db"},
		EnforcementPolicy{Enabled: true, Action: "kill", MinSeverity: "high", MatchFilename: "/opt/kill.me"},
		EnforcementPolicy{Enabled: true, Action: "monitor", MatchFilename: "/opt/monitor.only"},
		EnforcementPolicy{Enabled: false, Action: "alert", MatchFilename: "/opt/disabled"},
		EnforcementPolicy{Enabled: true, Action: "alert", EventTypes: []string{"unlinkat"}, MatchFilename: "/opt/unlink.only"},
		EnforcementPolicy{Enabled: true, Action: "alert", MatchDestIP: "203.0.113.9", MatchFilename: "/opt/dest"},
	))
	want := map[string]uint8{"secret.key": traceKeepName, "vault": traceKeepDir, "x.db": traceKeepName, "kill.me": traceKeepName}
	for name, flag := range want {
		if got[name] != flag {
			t.Errorf("%s = %d, want %d", name, got[name], flag)
		}
	}
	for _, name := range []string{"monitor.only", "disabled", "unlink.only", "dest"} {
		if _, ok := got[name]; ok {
			t.Errorf("%s listed", name)
		}
	}
	// A policy name shared with a built-in widens its bits, never narrows them.
	got = shedKeepNames(policySet(EnforcementPolicy{Enabled: true, Action: "alert", MatchFilename: "/etc/hosts"}))
	if got["hosts"] != traceKeepWrite|traceKeepName {
		t.Errorf("hosts = %d", got["hosts"])
	}
	if got["shadow"] != traceKeepName {
		t.Errorf("built-in lost: %v", got["shadow"])
	}
	if traceKeepBuiltin["hosts"] != traceKeepWrite {
		t.Fatal("shedKeepNames changed the built-in table")
	}
}

// The engine hands the keep names along with the routes, and follows
// policy changes.
func TestKillCandidateRoutingCarriesKeepNames(t *testing.T) {
	pe := NewPolicyEngine()
	var last killRoutes
	pe.SetKillCandidateRouting(func(r killRoutes) { last = r })
	if last.KeepNames["shadow"] != traceKeepName {
		t.Fatalf("built-ins not sent: %v", last.KeepNames)
	}
	addPolicy(t, pe, EnforcementPolicy{Name: "vault", Enabled: true, Action: "alert", MatchFilename: "/srv/vault/"})
	if last.KeepNames["vault"] != traceKeepDir {
		t.Fatalf("policy name not sent: %v", last.KeepNames["vault"])
	}
}

// The kernel and the agent hash names alike (trace_name_hash_byte vs
// traceNameHash) - covered for the route names by
// TestTracePriorityOpenNameRoute; the keep map uses the same hash.
func TestTraceKeepNameKeysMergeCollisions(t *testing.T) {
	keys := traceKeepNameKeys(map[string]uint8{"Shadow": traceKeepName, "shadow": traceKeepDir})
	if len(keys) != 1 || keys[traceNameHash("shadow")] != traceKeepName|traceKeepDir {
		t.Fatalf("keys = %v", keys)
	}
}
