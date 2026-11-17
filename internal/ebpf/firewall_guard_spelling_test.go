package ebpf

import (
	"errors"
	"testing"
	"time"
)

// The lockout guard reads entries the way the agent stores them,
// so a family-wide block in any spelling — or a set of blocks covering half
// a family or more — needs the same conntrack and escape hatch as
// 0.0.0.0/0 / ::/0.
func TestGuardReadsEntriesAsStored(t *testing.T) {
	tracked := &FullConfigAPI{Global: GlobalConfigAPI{EnableConntrack: true}}
	untracked := &FullConfigAPI{}
	for _, spelling := range []string{"0.0.0.0/0", "1.2.3.4/0", "0.0.0.0-255.255.255.255", "::ffff:0:0/96", "0::0/0", "::/0"} {
		in := FirewallSafetyInput{Config: untracked, Blocklist: []BlocklistEntry{{IP: spelling}}}
		if _, err := ValidateFirewallSafety(in); !errors.Is(err, ErrWildcardBlockNeedsConntrack) {
			t.Errorf("block %q without conntrack: %v", spelling, err)
		}
		in.Config = tracked
		if _, err := ValidateFirewallSafety(in); !errors.Is(err, ErrWildcardBlockNeedsAllowlist) {
			t.Errorf("block %q without an escape hatch: %v", spelling, err)
		}
		eg := FirewallSafetyInput{Config: untracked, EgressBlocklist: []EgressBlocklistEntry{{IP: spelling}}}
		if _, err := ValidateFirewallSafety(eg); !errors.Is(err, ErrWildcardBlockNeedsConntrack) {
			t.Errorf("egress block %q without conntrack: %v", spelling, err)
		}
		if !NeedsDataplaneExemptions(FirewallSafetyInput{Blocklist: []BlocklistEntry{{IP: spelling}}}) {
			t.Errorf("%q not recognised as needing the exemptions dataplane", spelling)
		}
	}

	// An IPv4-mapped prefix shorter than /96 lands in the IPv6 trie: it is no
	// IPv4 escape hatch.
	in := FirewallSafetyInput{Config: tracked, Blocklist: []BlocklistEntry{{IP: "0.0.0.0/0"}},
		Allowlist: []AllowlistEntry{{IP: "::ffff:0.0.0.0/95"}}}
	if _, err := ValidateFirewallSafety(in); !errors.Is(err, ErrWildcardBlockNeedsAllowlist) {
		t.Errorf("mapped /95 counted as an IPv4 escape hatch: %v", err)
	}
	in.Allowlist = []AllowlistEntry{{IP: "::ffff:203.0.113.7"}}
	if _, err := ValidateFirewallSafety(in); err != nil {
		t.Errorf("mapped IPv4 address refused as an IPv4 escape hatch: %v", err)
	}

	// Half a family or more without a /0 entry.
	for _, set := range [][]string{{"0.0.0.0/1", "128.0.0.0/1"}, {"0.0.0.1-255.255.255.255"}, {"0.0.0.0/1"}, {"::/1"}} {
		var bl []BlocklistEntry
		var eg []EgressBlocklistEntry
		for _, ip := range set {
			bl = append(bl, BlocklistEntry{IP: ip})
			eg = append(eg, EgressBlocklistEntry{IP: ip})
		}
		if _, err := ValidateFirewallSafety(FirewallSafetyInput{Config: tracked, Blocklist: bl}); !errors.Is(err, ErrWildcardBlockNeedsAllowlist) {
			t.Errorf("broad block %v without an escape hatch: %v", set, err)
		}
		if _, err := ValidateFirewallSafety(FirewallSafetyInput{Config: tracked, EgressBlocklist: eg}); !errors.Is(err, ErrEgressBlockTooBroad) {
			t.Errorf("broad egress block %v: %v", set, err)
		}
	}
	ok := FirewallSafetyInput{Config: tracked, Blocklist: []BlocklistEntry{{IP: "0.0.0.0/1"}}, Allowlist: []AllowlistEntry{{IP: "203.0.113.0/24"}}}
	if _, err := ValidateFirewallSafety(ok); err != nil {
		t.Errorf("broad block with an escape hatch: %v", err)
	}
	// Bogon-style blocks stay well under half a family.
	small := FirewallSafetyInput{Config: untracked, Blocklist: []BlocklistEntry{{IP: "224.0.0.0/4"}, {IP: "240.0.0.0/4"}, {IP: "10.0.0.0/8"}},
		EgressBlocklist: []EgressBlocklistEntry{{IP: "224.0.0.0/4"}}}
	if _, err := ValidateFirewallSafety(small); err != nil {
		t.Errorf("bogon blocks refused: %v", err)
	}
	// Expired entries never count.
	past := time.Now().Add(-time.Minute)
	gone := FirewallSafetyInput{Config: untracked, Blocklist: []BlocklistEntry{{IP: "0.0.0.0-255.255.255.255", ExpiresAt: &past}}}
	if _, err := ValidateFirewallSafety(gone); err != nil {
		t.Errorf("expired family block judged: %v", err)
	}
	if code, ok := FirewallErrorCode(ErrEgressBlockTooBroad); !ok || code != "EGRESS_BLOCK_TOO_BROAD" {
		t.Errorf("code %q", code)
	}
}
