package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Entries become prefixes, never expanded addresses.
func TestIPListKeys(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"192.0.2.1", "192.0.2.1"},
		{" 192.0.2.1 ", "192.0.2.1"},
		{"192.0.2.1/32", "192.0.2.1"},
		{"192.0.2.77/24", "192.0.2.0/24"},
		{"192.0.0.0/15", "192.0.0.0/15"},
		{"2001:db8::/64", "2001:db8::/64"},
		{"2001:db8::1", "2001:db8::1"},
		{"::ffff:192.0.2.1", "192.0.2.1"},
		{"::ffff:192.0.2.0/120", "192.0.2.0/24"},
		{"0.0.0.0/0", "0.0.0.0/0"},
		{"::/0", "::/0"},
		{"10.0.0.1-10.0.0.3", "10.0.0.1,10.0.0.2/31"},
		{"10.0.0.0-10.0.0.255", "10.0.0.0/24"},
		{"0.0.0.0-255.255.255.255", "0.0.0.0/0"},
		{"255.255.255.254-255.255.255.255", "255.255.255.254/31"},
		{"192.0.2.5-192.0.2.5", "192.0.2.5"},
	} {
		got, err := IPListKeys(tc.in)
		if err != nil {
			t.Errorf("%q: %v", tc.in, err)
			continue
		}
		if s := strings.Join(got, ","); s != tc.want {
			t.Errorf("%q: %s, want %s", tc.in, s, tc.want)
		}
	}
	for _, bad := range []string{"", "x", "10.0.0.0/33", "10.0.0.5-10.0.0.1", "2001:db8::1-2001:db8::2", "fe80::1%eth0", "10.0.0.1-"} {
		if _, err := IPListKeys(bad); !errors.Is(err, ErrInvalidIPEntry) {
			t.Errorf("%q accepted or wrong error: %v", bad, err)
		}
	}
}

// The minimal CIDR cover of any range is exact and at most 62 prefixes.
func TestIPv4RangeCover(t *testing.T) {
	for _, r := range [][2]string{{"0.0.0.1", "255.255.255.254"}, {"10.0.0.7", "10.0.3.200"}, {"1.2.3.4", "1.2.3.4"}} {
		ps, err := IPListPrefixes(r[0] + "-" + r[1])
		if err != nil {
			t.Fatal(err)
		}
		if len(ps) > 62 {
			t.Fatalf("%v: %d prefixes", r, len(ps))
		}
		var total uint64
		for i, p := range ps {
			total += uint64(1) << (32 - p.Bits())
			if i > 0 && !ps[i-1].Addr().Less(p.Addr()) {
				t.Fatalf("%v: prefixes out of order", r)
			}
		}
		first := binary.BigEndian.Uint32(mustAddr4(r[0]))
		last := binary.BigEndian.Uint32(mustAddr4(r[1]))
		if total != uint64(last)-uint64(first)+1 {
			t.Fatalf("%v: cover holds %d addresses, range %d", r, total, uint64(last)-uint64(first)+1)
		}
	}
}

func mustAddr4(s string) []byte {
	ps, err := IPListPrefixes(s)
	if err != nil {
		panic(err)
	}
	b := ps[0].Addr().As4()
	return b[:]
}

// The XDP walk visits at most LIST_WALK_MAX nested entries per address.
func TestValidateIPListNesting(t *testing.T) {
	now := time.Now()
	soon := now.Add(time.Hour)
	block := func(entries ...string) []BlocklistEntry {
		var out []BlocklistEntry
		for _, e := range entries {
			ip, expiring := strings.CutSuffix(e, "~")
			be := BlocklistEntry{IP: ip}
			if expiring {
				be.ExpiresAt = &soon
			}
			out = append(out, be)
		}
		return out
	}
	for _, tc := range []struct {
		name    string
		entries []BlocklistEntry
		ok      bool
	}{
		{"permanent nesting is unlimited", block("10.0.0.1", "10.0.0.0/31", "10.0.0.0/30", "10.0.0.0/29", "10.0.0.0/28", "10.0.0.0/8"), true},
		{"three expiring then live", block("10.0.0.1~", "10.0.0.0/31~", "10.0.0.0/30~", "10.0.0.0/8"), true},
		{"four expiring then live", block("10.0.0.1~", "10.0.0.0/31~", "10.0.0.0/30~", "10.0.0.0/29~", "10.0.0.0/8"), false},
		{"four expiring, nothing beyond", block("10.0.0.1~", "10.0.0.0/31~", "10.0.0.0/30~", "10.0.0.0/29~"), true},
		{"permanent in reach", block("10.0.0.1~", "10.0.0.0/31~", "10.0.0.0/30", "10.0.0.0/29~", "10.0.0.0/28~", "10.0.0.0/8"), true},
		{"v6 too deep", block("2001:db8::1~", "2001:db8::/64~", "2001:db8::/56~", "2001:db8::/48~", "::/0"), false},
		{"families apart", block("10.0.0.1~", "10.0.0.0/31~", "10.0.0.0/30~", "10.0.0.0/29~", "::/0"), true},
	} {
		err := ValidateIPListNesting(nil, tc.entries, now)
		if tc.ok && err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
		if !tc.ok && !errors.Is(err, ErrBlocklistNestingTooDeep) {
			t.Errorf("%s: accepted (%v)", tc.name, err)
		}
	}
	allow := []AllowlistEntry{{IP: "10.0.0.1", ExpiresAt: &soon}, {IP: "10.0.0.0/31", ExpiresAt: &soon}, {IP: "10.0.0.0/30", ExpiresAt: &soon}, {IP: "10.0.0.0/29", ExpiresAt: &soon}, {IP: "10.0.0.0/8"}}
	if err := ValidateIPListNesting(allow, nil, now); !errors.Is(err, ErrAllowlistNestingTooDeep) {
		t.Fatalf("deep allowlist: %v", err)
	}
	if code, ok := FirewallErrorCode(fmt.Errorf("wrapped: %w", ErrAllowlistNestingTooDeep)); !ok || code != "ALLOWLIST_NESTING_TOO_DEEP" {
		t.Fatalf("code %q", code)
	}
	if _, err := ValidateFirewallSafety(FirewallSafetyInput{Blocklist: block("10.0.0.1~", "10.0.0.0/31~", "10.0.0.0/30~", "10.0.0.0/29~", "10.0.0.0/8"), Now: now}); !errors.Is(err, ErrBlocklistNestingTooDeep) {
		t.Fatalf("lockout guard skipped the nesting check: %v", err)
	}
}

// Layout: the Go values marshal to the C structs byte for byte (sizes and
// field offsets compiled from wafio_common.h).
func TestListValueLayout(t *testing.T) {
	if n := binary.Size(AllowVal{}); n != 88 {
		t.Fatalf("AllowVal %d bytes, struct allow_val is 88", n)
	}
	if n := binary.Size(BlockVal{}); n != 40 {
		t.Fatalf("BlockVal %d bytes, struct block_val is 40", n)
	}
	src := nativePacketTypes +
		bpfSourceDefines(t, "wafio_common.h", "ALLOW_MAX_SCOPES", "ALLOW_F_ALL", "LIST_WALK_MAX") +
		bpfSourceStruct(t, "wafio_common.h", "allow_scope") +
		bpfSourceStruct(t, "wafio_common.h", "list_val") +
		bpfSourceStruct(t, "wafio_common.h", "allow_val") +
		bpfSourceStruct(t, "wafio_common.h", "block_val") + `
#include <stddef.h>
int main(void) {
  printf("allow %zu %zu %zu %zu %zu\n", sizeof(struct allow_val), offsetof(struct allow_val, flags),
         offsetof(struct allow_val, prefixlen), offsetof(struct allow_val, scopes), offsetof(struct allow_val, pad));
  printf("block %zu %zu\n", sizeof(struct block_val), offsetof(struct block_val, prefixlen));
  printf("head %zu %zu\n", offsetof(struct list_val, hit_count), offsetof(struct list_val, prefixlen));
  printf("consts %d %u %d\n", ALLOW_MAX_SCOPES, ALLOW_F_ALL, LIST_WALK_MAX);
  return 0;
}
`
	got := runNativeC(t, "list_value_layout", src)
	want := fmt.Sprintf("allow 88 24 32 36 84\nblock 40 32\nhead 16 32\nconsts %d %d %d\n", allowMaxScopes, AllowFlagAll, listWalkMax)
	if got != want {
		t.Fatalf("C layout\n%s\nwant\n%s", got, want)
	}
}

func TestWildcardPreservesAddressFamily(t *testing.T) {
	v4, v6 := IPKeyWildcard("0.0.0.0/0"), IPKeyWildcard("::/0")
	if v4 == v6 {
		t.Fatal("IPv4 wildcard also matches IPv6")
	}
	if !v4.IsWildcard() || !v6.IsWildcard() {
		t.Fatal("wildcard unrecognized")
	}
}
