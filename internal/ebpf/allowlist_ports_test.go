package ebpf

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"
	"unsafe"
)

// Port-scoped allowlist entries: parsing and normalisation, the lockout-escape
// rule, the guard, the nesting check and the BPF value layout. The XDP walk
// itself runs natively below (TestXDPAllowScopeWalk) and under
// BPF_PROG_TEST_RUN in TestKernelAllowlistPorts* (lab).

func ps(proto string, from, to int) PortScope { return PortScope{Proto: proto, From: from, To: to} }

func TestNormalizePortScopes(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []PortScope
		want string
	}{
		{"empty is every port", nil, ""},
		{"single port gets To", []PortScope{ps("tcp", 22, 0)}, "22/tcp"},
		{"proto case and space", []PortScope{ps(" TCP ", 5432, 5432)}, "5432/tcp"},
		{"sorted by port", []PortScope{ps("tcp", 5432, 0), ps("tcp", 22, 0)}, "22/tcp,5432/tcp"},
		{"overlap merged", []PortScope{ps("tcp", 1000, 2000), ps("tcp", 1500, 2500)}, "1000-2500/tcp"},
		{"adjacent merged", []PortScope{ps("udp", 1000, 1999), ps("udp", 2000, 0)}, "1000-2000/udp"},
		{"other proto not merged", []PortScope{ps("tcp", 53, 0), ps("udp", 53, 0)}, "53/tcp,53/udp"},
		{"any absorbs tcp inside", []PortScope{ps("any", 1, 1024), ps("tcp", 22, 0), ps("udp", 53, 0)}, "1-1024/any"},
		{"any keeps tcp partly outside", []PortScope{ps("any", 1, 1024), ps("tcp", 1000, 2000)}, "1-1024/any,1000-2000/tcp"},
		{"edges", []PortScope{ps("tcp", 1, 0), ps("tcp", 65535, 0)}, "1/tcp,65535/tcp"},
		{"nine items merge to one", func() []PortScope {
			var out []PortScope
			for p := 100; p < 109; p++ {
				out = append(out, ps("tcp", p, 0))
			}
			return out
		}(), "100-108/tcp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizePortScopes(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if k := PortScopesKey(got); k != tc.want {
				t.Fatalf("got %q want %q", k, tc.want)
			}
			if tc.want == "" && got != nil {
				t.Fatalf("empty input must stay nil (every port), got %#v", got)
			}
		})
	}
	eight := make([]PortScope, 0, 9)
	for i := 0; i < 9; i++ {
		eight = append(eight, ps("tcp", 1000+i*10, 0))
	}
	if _, err := NormalizePortScopes(eight[:8]); err != nil {
		t.Fatalf("8 items: %v", err)
	}
	for _, tc := range []struct {
		name string
		in   []PortScope
		want error
	}{
		{"no proto", []PortScope{ps("", 22, 0)}, ErrInvalidPorts},
		{"icmp", []PortScope{ps("icmp", 22, 0)}, ErrInvalidPorts},
		{"port 0", []PortScope{ps("tcp", 0, 0)}, ErrInvalidPorts},
		{"port 65536", []PortScope{ps("tcp", 65536, 0)}, ErrInvalidPorts},
		{"to 65536", []PortScope{ps("tcp", 1, 65536)}, ErrInvalidPorts},
		{"negative", []PortScope{ps("tcp", -1, 0)}, ErrInvalidPorts},
		{"reversed", []PortScope{ps("tcp", 2000, 1000)}, ErrInvalidPorts},
		{"nine distinct", eight, ErrAllowlistPortsTooMany},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NormalizePortScopes(tc.in); !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
		})
	}
}

func TestLockoutEscape(t *testing.T) {
	soon := time.Now().Add(time.Hour)
	for _, tc := range []struct {
		name  string
		entry AllowlistEntry
		ssh   []uint16
		want  bool
	}{
		{"every port", AllowlistEntry{IP: "198.51.100.7"}, nil, true},
		{"every port expiring", AllowlistEntry{IP: "198.51.100.7", ExpiresAt: &soon}, nil, false},
		{"non-SSH scope", AllowlistEntry{IP: "198.51.100.7", Ports: []PortScope{ps("tcp", 5432, 0)}}, nil, false},
		{"22/tcp assumed", AllowlistEntry{IP: "198.51.100.7", Ports: []PortScope{ps("tcp", 22, 0)}}, nil, true},
		{"22/udp", AllowlistEntry{IP: "198.51.100.7", Ports: []PortScope{ps("udp", 22, 0)}}, nil, false},
		{"any range covers 22", AllowlistEntry{IP: "198.51.100.7", Ports: []PortScope{ps("any", 1, 1024)}}, nil, true},
		{"tcp range covers 22", AllowlistEntry{IP: "198.51.100.7", Ports: []PortScope{ps("tcp", 20, 25)}}, nil, true},
		{"detected 2222", AllowlistEntry{IP: "198.51.100.7", Ports: []PortScope{ps("tcp", 2222, 0)}}, []uint16{2222}, true},
		{"22 but sshd on 2222", AllowlistEntry{IP: "198.51.100.7", Ports: []PortScope{ps("tcp", 22, 0)}}, []uint16{2222}, false},
		{"scoped 22 expiring", AllowlistEntry{IP: "198.51.100.7", ExpiresAt: &soon, Ports: []PortScope{ps("tcp", 22, 0)}}, nil, false},
		{"none sentinel", AllowlistEntry{IP: "198.51.100.7", Ports: []PortScope{{Proto: portProtoNone}}}, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := LockoutEscape(tc.entry, tc.ssh); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestValidateAllowlistPorts(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Hour)
	scoped := []PortScope{ps("tcp", 22, 0)}
	for _, spelling := range []string{"0.0.0.0/0", "::/0", "0.0.0.0-255.255.255.255", "::ffff:0:0/96", "10.1.2.3/0"} {
		err := ValidateAllowlistPorts([]AllowlistEntry{{IP: spelling, Ports: scoped}}, now)
		if !errors.Is(err, ErrAllowlistWildcardScoped) {
			t.Errorf("%s with ports: %v", spelling, err)
		}
		if code, _ := FirewallErrorCode(err); code != "ALLOWLIST_WILDCARD_SCOPED" {
			t.Errorf("%s: code %q", spelling, code)
		}
		if err := ValidateAllowlistPorts([]AllowlistEntry{{IP: spelling}}, now); err != nil {
			t.Errorf("%s without ports: %v", spelling, err)
		}
	}
	conflict := []AllowlistEntry{{IP: "10.0.0.0/24", Ports: scoped}, {IP: "10.0.0.1/24", Ports: []PortScope{ps("tcp", 80, 0)}}}
	if err := ValidateAllowlistPorts(conflict, now); !errors.Is(err, ErrInvalidPorts) {
		t.Fatalf("two spellings of one prefix with different ports: %v", err)
	}
	// A range shares its /32 with a single address: the ports must agree.
	if err := ValidateAllowlistPorts([]AllowlistEntry{{IP: "10.0.0.5-10.0.0.6"}, {IP: "10.0.0.5", Ports: scoped}}, now); err == nil {
		t.Fatal("range and address with different ports on a shared prefix accepted")
	}
	same := []AllowlistEntry{{IP: "10.0.0.0/24", Ports: scoped}, {IP: "10.0.0.1/24", Ports: []PortScope{ps("TCP", 22, 22)}}}
	if err := ValidateAllowlistPorts(same, now); err != nil {
		t.Fatalf("same ports, two spellings: %v", err)
	}
	expired := []AllowlistEntry{{IP: "10.0.0.0/24", Ports: scoped}, {IP: "10.0.0.1/24", ExpiresAt: &past}}
	if err := ValidateAllowlistPorts(expired, now); err != nil {
		t.Fatalf("expired entry must not conflict: %v", err)
	}
	var many []PortScope
	for i := 0; i < 9; i++ {
		many = append(many, ps("udp", 100+2*i, 0))
	}
	err := ValidateAllowlistPorts([]AllowlistEntry{{IP: "10.0.0.1", Ports: many}}, now)
	if code, _ := FirewallErrorCode(err); code != "ALLOWLIST_PORTS_TOO_MANY" {
		t.Fatalf("too many: %v (%s)", err, code)
	}
	err = ValidateAllowlistPorts([]AllowlistEntry{{IP: "10.0.0.1", Ports: []PortScope{ps("sctp", 1, 0)}}}, now)
	if code, _ := FirewallErrorCode(err); code != "INVALID_PORTS" {
		t.Fatalf("bad proto: %v (%s)", err, code)
	}
	if code, _ := FirewallErrorCode(ErrAllowlistPortsUnsupported); code != "ALLOWLIST_PORTS_UNSUPPORTED" {
		t.Fatalf("unsupported code %q", code)
	}
}

func guardConfig() *FullConfigAPI {
	cfg := DefaultFullConfigAPI()
	cfg.Global.EnableConntrack = true
	return &cfg
}

func hasWarning(ws []FirewallWarning, code string) bool {
	for _, w := range ws {
		if w.Code == code {
			return true
		}
	}
	return false
}

// A permanent entry is a lockout escape only with every port or a
// TCP/any scope on an SSH port; a scope for other ports is not.
func TestGuardScopedAllowlistEscapeHatch(t *testing.T) {
	soon := time.Now().Add(time.Hour)
	block := []BlocklistEntry{{IP: "0.0.0.0/0"}}
	for _, tc := range []struct {
		name        string
		allow       []AllowlistEntry
		ssh         []uint16
		ok, assumed bool
	}{
		{"every port", []AllowlistEntry{{IP: "198.51.100.0/24"}}, nil, true, false},
		{"5432 only", []AllowlistEntry{{IP: "198.51.100.0/24", Ports: []PortScope{ps("tcp", 5432, 0)}}}, nil, false, false},
		{"22/tcp assumed", []AllowlistEntry{{IP: "198.51.100.0/24", Ports: []PortScope{ps("tcp", 22, 0)}}}, nil, true, true},
		{"22/tcp detected", []AllowlistEntry{{IP: "198.51.100.0/24", Ports: []PortScope{ps("tcp", 22, 0)}}}, []uint16{22}, true, false},
		{"2222 detected", []AllowlistEntry{{IP: "198.51.100.0/24", Ports: []PortScope{ps("tcp", 2222, 0)}}}, []uint16{2222}, true, false},
		{"22 but sshd on 2222", []AllowlistEntry{{IP: "198.51.100.0/24", Ports: []PortScope{ps("tcp", 22, 0)}}}, []uint16{2222}, false, false},
		{"range covers 22", []AllowlistEntry{{IP: "198.51.100.0/24", Ports: []PortScope{ps("any", 1, 1024)}}}, []uint16{22}, true, false},
		{"22/udp", []AllowlistEntry{{IP: "198.51.100.0/24", Ports: []PortScope{ps("udp", 22, 0)}}}, nil, false, false},
		{"expiring 22", []AllowlistEntry{{IP: "198.51.100.0/24", ExpiresAt: &soon, Ports: []PortScope{ps("tcp", 22, 0)}}}, nil, false, false},
		{"wrong family", []AllowlistEntry{{IP: "2001:db8::/48", Ports: []PortScope{ps("tcp", 22, 0)}}}, nil, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ws, err := ValidateFirewallSafety(FirewallSafetyInput{Config: guardConfig(), Blocklist: block, Allowlist: tc.allow, SSHPorts: tc.ssh})
			if tc.ok != (err == nil) {
				t.Fatalf("err %v, want ok=%v", err, tc.ok)
			}
			if err != nil {
				if code, _ := FirewallErrorCode(err); code != "WILDCARD_BLOCK_NEEDS_ALLOWLIST" {
					t.Fatalf("code %q", code)
				}
				return
			}
			if got := hasWarning(ws, WarnSSHPortAssumed); got != tc.assumed {
				t.Fatalf("SSH_PORT_ASSUMED %v want %v (%v)", got, tc.assumed, ws)
			}
		})
	}
	// Half a family blocked without /0 needs the same escape hatch.
	_, err := ValidateFirewallSafety(FirewallSafetyInput{Config: guardConfig(),
		Blocklist: []BlocklistEntry{{IP: "0.0.0.0/1"}, {IP: "128.0.0.0/1"}},
		Allowlist: []AllowlistEntry{{IP: "198.51.100.0/24", Ports: []PortScope{ps("tcp", 443, 0)}}}})
	if code, _ := FirewallErrorCode(err); code != "WILDCARD_BLOCK_NEEDS_ALLOWLIST" {
		t.Fatalf("broad block with a non-SSH scope: %v", err)
	}
	// Ingress Deny All with only a 22 ALLOW rule still warns once.
	ws, err := ValidateFirewallSafety(FirewallSafetyInput{Config: guardConfig(), Blocklist: block,
		Allowlist:        []AllowlistEntry{{IP: "198.51.100.0/24", Ports: []PortScope{ps("tcp", 22, 0)}}},
		PortPolicyConfig: &PortPolicyConfigAPI{Enabled: true, DefaultIngress: "deny", DefaultEgress: "allow"},
		PortPolicies:     []PortPolicyAPI{{Port: 22, Proto: "tcp", Direction: "ingress", Action: "allow"}}})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, w := range ws {
		if w.Code == WarnSSHPortAssumed {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("SSH_PORT_ASSUMED %d times: %v", n, ws)
	}
	// A host that cannot enforce scopes (control plane: feature not
	// reported) gets no escape hatch from a scoped entry; an entry for every
	// port still counts.
	scopedHatch := []AllowlistEntry{{IP: "198.51.100.0/24", Ports: []PortScope{ps("tcp", 22, 0)}}}
	_, err = ValidateFirewallSafety(FirewallSafetyInput{Config: guardConfig(), Blocklist: block, Allowlist: scopedHatch,
		SSHPorts: []uint16{22}, AllowlistPortsUnsupported: true})
	if code, _ := FirewallErrorCode(err); code != "WILDCARD_BLOCK_NEEDS_ALLOWLIST" {
		t.Fatalf("scoped hatch on a host without the feature: %v", err)
	}
	if _, err := ValidateFirewallSafety(FirewallSafetyInput{Config: guardConfig(), Blocklist: block,
		Allowlist: append(scopedHatch, AllowlistEntry{IP: "203.0.113.9"}), SSHPorts: []uint16{22}, AllowlistPortsUnsupported: true}); err != nil {
		t.Fatalf("full hatch on a host without the feature: %v", err)
	}
	// The guard refuses a scoped /0 and conflicting spellings outright.
	_, err = ValidateFirewallSafety(FirewallSafetyInput{Config: guardConfig(),
		Allowlist: []AllowlistEntry{{IP: "::/0", Ports: []PortScope{ps("tcp", 22, 0)}}}})
	if !errors.Is(err, ErrAllowlistWildcardScoped) {
		t.Fatalf("scoped ::/0: %v", err)
	}
}

func TestGuardGeoAllowNoEscapeWarning(t *testing.T) {
	cfg := guardConfig()
	cfg.Global.MonitorOnly = false
	cfg.Global.EnableGeoblock = true
	base := FirewallSafetyInput{Config: cfg, GeoMode: GeoModeAllow, GeoAllowed: []string{"DE"}, GeoAllowAcknowledged: true}
	ws, err := ValidateFirewallSafety(base)
	if err != nil {
		t.Fatal(err)
	}
	if !hasWarning(ws, WarnGeoAllowNoEscape) || !hasWarning(ws, WarnGeoAllowActive) {
		t.Fatalf("no escape: %v", ws)
	}
	base.Allowlist = []AllowlistEntry{{IP: "198.51.100.7", Ports: []PortScope{ps("tcp", 5432, 0)}}}
	if ws, _ = ValidateFirewallSafety(base); !hasWarning(ws, WarnGeoAllowNoEscape) {
		t.Fatalf("a 5432 scope is no escape: %v", ws)
	}
	base.Allowlist = []AllowlistEntry{{IP: "2001:db8::7", Ports: []PortScope{ps("tcp", 22, 0)}}}
	if ws, _ = ValidateFirewallSafety(base); hasWarning(ws, WarnGeoAllowNoEscape) {
		t.Fatalf("an IPv6 SSH scope is an escape: %v", ws)
	}
	cfg.Global.MonitorOnly = true
	base.Allowlist = nil
	if ws, _ = ValidateFirewallSafety(base); hasWarning(ws, WarnGeoAllowNoEscape) {
		t.Fatalf("monitor mode warns: %v", ws)
	}
}

// A scoped entry does not decide for ICMP or other ports, so the walk
// passes it like an expired one; four of them above an address hide what lies
// beyond.
func TestValidateIPListNestingScoped(t *testing.T) {
	now := time.Now()
	scoped := func(ip string, port int) AllowlistEntry {
		return AllowlistEntry{IP: ip, Ports: []PortScope{ps("tcp", port, 0)}}
	}
	deep := []AllowlistEntry{scoped("192.0.2.10", 22), scoped("192.0.2.10/31", 80), scoped("192.0.2.8/30", 443),
		scoped("192.0.2.8/29", 8080), {IP: "192.0.0.0/8"}}
	err := ValidateIPListNesting(deep, nil, now)
	if !errors.Is(err, ErrAllowlistNestingTooDeep) {
		t.Fatalf("four scoped levels above a full /8: %v", err)
	}
	ok := append([]AllowlistEntry{}, deep[:3]...)
	ok = append(ok, AllowlistEntry{IP: "192.0.2.8/29"}, AllowlistEntry{IP: "192.0.0.0/8"})
	if err := ValidateIPListNesting(ok, nil, now); err != nil {
		t.Fatalf("a permanent full /29 within reach: %v", err)
	}
	if err := ValidateIPListNesting(deep[:4], nil, now); err != nil {
		t.Fatalf("four scoped levels and nothing beyond: %v", err)
	}
}

// The Go and C layouts of allow_val agree (88 bytes, scopes at 36).
func TestAllowValLayout(t *testing.T) {
	var v AllowVal
	if n := binary.Size(v); n != 88 {
		t.Fatalf("binary size %d", n)
	}
	if off := unsafe.Offsetof(v.Scopes); off != 36 {
		t.Fatalf("scopes at %d", off)
	}
	if n := binary.Size(AllowScope{}); n != 6 {
		t.Fatalf("scope size %d", n)
	}
	out := runNativeC(t, "allow_val_layout", nativePacketTypes+
		bpfSourceDefines(t, "wafio_common.h", "ALLOW_MAX_SCOPES")+
		bpfSourceStruct(t, "wafio_common.h", "allow_scope")+
		bpfSourceStruct(t, "wafio_common.h", "allow_val")+`
#include <stddef.h>
int main(void) {
  printf("%zu %zu %zu %zu\n", sizeof(struct allow_val), offsetof(struct allow_val, scopes),
         sizeof(struct allow_scope), offsetof(struct allow_val, pad));
  return 0;
}
`)
	if strings.TrimSpace(out) != "88 36 6 84" {
		t.Fatalf("C layout %q", out)
	}
}

func TestAllowValScopesRoundTrip(t *testing.T) {
	var v AllowVal
	if err := allowValScopes(&v, nil); err != nil || v.Flags != AllowFlagAll || v.NScopes != 0 {
		t.Fatalf("full: %+v %v", v, err)
	}
	if got := portScopesOfAllowVal(v); got != nil {
		t.Fatalf("full decodes to %v", got)
	}
	in := []PortScope{ps("tcp", 5432, 0), ps("any", 53, 0), ps("udp", 6000, 6010)}
	if err := allowValScopes(&v, in); err != nil {
		t.Fatal(err)
	}
	if v.Flags != 0 || v.NScopes != 3 || v.Scopes[0] != (AllowScope{Lo: 53, Hi: 53, Proto: 0}) ||
		v.Scopes[1] != (AllowScope{Lo: 5432, Hi: 5432, Proto: 6}) || v.Scopes[2] != (AllowScope{Lo: 6000, Hi: 6010, Proto: 17}) {
		t.Fatalf("encoded %+v", v)
	}
	if got := PortScopesKey(portScopesOfAllowVal(v)); got != "53/any,5432/tcp,6000-6010/udp" {
		t.Fatalf("decoded %q", got)
	}
	// A value that allows nothing (no ALLOW_F_ALL, no scope) is never listed
	// as every port.
	if got := portScopesOfAllowVal(AllowVal{}); len(got) != 1 || got[0].Proto != portProtoNone {
		t.Fatalf("empty value decodes to %v", got)
	}
	if _, err := NormalizePortScopes(portScopesOfAllowVal(AllowVal{})); err == nil {
		t.Fatal("the none sentinel must not normalise")
	}
}

// TestXDPAllowScopeWalk runs the allowlist walk of wafio_xdp.c natively with
// the LPM trie mocked: scope matching (protocol, range edges, ICMP, no
// port), the walk past a non-deciding entry to a shorter prefix, expiry, the
// LIST_WALK_MAX limit, a corrupt nscopes and hit counting.
func TestXDPAllowScopeWalk(t *testing.T) {
	src := nativePacketTypes + `
#define bpf_ntohl(x) __builtin_bswap32(x)
#define IPPROTO_ICMP 1
` + bpfSourceDefines(t, "wafio_common.h", "LIST_WALK_MAX", "ALLOW_") +
		bpfSourceDefines(t, "wafio_xdp.c", "LISTS_") +
		bpfSourceStruct(t, "wafio_common.h", "subnet_v4_key") +
		bpfSourceStruct(t, "wafio_common.h", "allow_scope") +
		bpfSourceStruct(t, "wafio_common.h", "allow_val") + `
static int wafio_allow4;
struct ent { __u32 plen; __u32 addr; struct allow_val v; };
static struct ent trie[8]; static int ntrie;
static void put(__u32 a, __u32 plen, __u32 flags, __u64 expires) {
  struct ent *e = &trie[ntrie++]; memset(e, 0, sizeof *e);
  e->plen = plen; e->addr = plen ? a & (0xffffffffu << (32 - plen)) : 0;
  e->v.prefixlen = plen; e->v.flags = flags; e->v.expires_ns = expires;
}
static void scope(__u16 lo, __u16 hi, __u8 proto) {
  struct allow_val *v = &trie[ntrie - 1].v; v->scopes[v->nscopes].lo = lo; v->scopes[v->nscopes].hi = hi; v->scopes[v->nscopes].proto = proto; v->nscopes++;
}
static void *bpf_map_lookup_elem(void *map, const void *key) {
  const struct subnet_v4_key *k = key; struct ent *best = NULL;
  __u32 a = bpf_ntohl(k->addr);
  if (map != &wafio_allow4) return NULL;
  for (int i = 0; i < ntrie; i++) {
    struct ent *e = &trie[i];
    __u32 mask = e->plen ? 0xffffffffu << (32 - e->plen) : 0;
    if (e->plen <= k->prefixlen && (a & mask) == e->addr && (!best || e->plen > best->plen)) best = e;
  }
  return best ? &best->v : NULL;
}
` + bpfSourceHelper(t, "wafio_xdp.c", "allow_scope_hit") + "\n" +
		bpfSourceHelper(t, "wafio_xdp.c", "allow_decides") + "\n" +
		bpfSourceHelper(t, "wafio_xdp.c", "allow_walk_v4") + `
static const __u64 now = 1000000;
static const __u32 SRC = 0xc000020a; /* 192.0.2.10 */
static int walk(__u8 proto, __u16 dport) { return allow_walk_v4(bpf_ntohl(SRC), now, LISTS_L4(proto, dport)); }
static int fails;
#define EXPECT(name, got, want) do { int g = (got); if (g != (want)) { printf("FAIL %s: got %d want %d\n", name, g, want); fails++; } } while (0)
int main(void) {
  /* /32 scoped to 22/tcp only. */
  ntrie = 0; put(SRC, 32, 0, 0); scope(22, 22, IPPROTO_TCP);
  EXPECT("22/tcp", walk(IPPROTO_TCP, 22), 32);
  EXPECT("80/tcp", walk(IPPROTO_TCP, 80), -1);
  EXPECT("22/udp", walk(IPPROTO_UDP, 22), -1);
  EXPECT("icmp", walk(IPPROTO_ICMP, 0), -1);
  EXPECT("icmp with port bits", walk(IPPROTO_ICMP, 22), -1);
  EXPECT("tcp no port", walk(IPPROTO_TCP, 0), -1);
  EXPECT("hit only on decider", (int)trie[0].v.hit_count, 1);
  /* ... under a full /24: other ports and ICMP fall to the /24. */
  put(SRC, 24, ALLOW_F_ALL, 0);
  EXPECT("nested 22", walk(IPPROTO_TCP, 22), 32);
  EXPECT("nested 80", walk(IPPROTO_TCP, 80), 24);
  EXPECT("nested icmp", walk(IPPROTO_ICMP, 0), 24);
  /* ... under a /24 scoped to 443: 22 stays /32, 443 /24, 80 nothing. */
  ntrie = 0; put(SRC, 32, 0, 0); scope(22, 22, IPPROTO_TCP); put(SRC, 24, 0, 0); scope(443, 443, IPPROTO_TCP);
  EXPECT("443 via /24", walk(IPPROTO_TCP, 443), 24);
  EXPECT("80 nowhere", walk(IPPROTO_TCP, 80), -1);
  /* An expired /32 falls through to the /24. */
  ntrie = 0; put(SRC, 32, 0, 1); scope(22, 22, IPPROTO_TCP); put(SRC, 24, 0, 0); scope(22, 22, IPPROTO_TCP);
  EXPECT("expired /32", walk(IPPROTO_TCP, 22), 24);
  /* any = TCP and UDP; range edges. */
  ntrie = 0; put(SRC, 32, 0, 0); scope(1000, 2000, 0);
  EXPECT("any tcp", walk(IPPROTO_TCP, 1500), 32);
  EXPECT("any udp", walk(IPPROTO_UDP, 1000), 32);
  EXPECT("edge hi", walk(IPPROTO_UDP, 2000), 32);
  EXPECT("below", walk(IPPROTO_TCP, 999), -1);
  EXPECT("above", walk(IPPROTO_TCP, 2001), -1);
  EXPECT("any not icmp", walk(IPPROTO_ICMP, 1500), -1);
  /* Only the first nscopes count; a corrupt count reads at most 8. */
  ntrie = 0; put(SRC, 32, 0, 0); for (int i = 0; i < 8; i++) scope(100 + i, 100 + i, IPPROTO_TCP);
  EXPECT("eighth scope", walk(IPPROTO_TCP, 107), 32);
  trie[0].v.nscopes = 2;
  EXPECT("past nscopes", walk(IPPROTO_TCP, 103), -1);
  trie[0].v.nscopes = 200;
  EXPECT("corrupt nscopes", walk(IPPROTO_TCP, 107), 32);
  EXPECT("corrupt nscopes miss", walk(IPPROTO_TCP, 108), -1);
  /* lo 0 never matches. */
  ntrie = 0; put(SRC, 32, 0, 0); scope(0, 65535, IPPROTO_TCP);
  EXPECT("lo 0", walk(IPPROTO_TCP, 80), -1);
  /* Four non-deciding levels exhaust the walk before the full /8. */
  ntrie = 0;
  put(SRC, 32, 0, 0); scope(1, 1, IPPROTO_TCP); put(SRC, 31, 0, 0); scope(2, 2, IPPROTO_TCP);
  put(SRC, 30, 0, 0); scope(3, 3, IPPROTO_TCP); put(SRC, 29, 0, 0); scope(4, 4, IPPROTO_TCP);
  put(SRC, 8, ALLOW_F_ALL, 0);
  EXPECT("walk limit", walk(IPPROTO_TCP, 80), -1);
  trie[3].v.flags = ALLOW_F_ALL;
  EXPECT("fourth level full", walk(IPPROTO_TCP, 80), 29);
  /* A scoped /0 decides only in scope (the control plane refuses one). */
  ntrie = 0; put(SRC, 0, 0, 0); scope(22, 22, IPPROTO_TCP);
  EXPECT("scoped /0 in scope", walk(IPPROTO_TCP, 22), 0);
  EXPECT("scoped /0 out of scope", walk(IPPROTO_TCP, 23), -1);
  return fails ? 1 : 0;
}
`
	out := runNativeC(t, "xdp_allow_scope_walk", src)
	if strings.Contains(out, "FAIL") {
		t.Fatal(out)
	}
}
