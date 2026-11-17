package ebpf

import "testing"

func TestExpandIPRangeRejectsPartialAndUnsupportedRanges(t *testing.T) {
	for _, s := range []string{"10.0.0.0/8", "10.0.0.2-10.0.0.1", "::1-::2", "invalid"} {
		if ips, err := ExpandIPRange(s, 10000); err == nil || len(ips) != 0 {
			t.Errorf("%s: partial/invalid range accepted (%d): %v", s, len(ips), err)
		}
	}
	for _, s := range []string{"10.0.0.0/24", "10.0.0.1-10.0.0.3", "2001:db8::/126", "255.255.255.254-255.255.255.255"} {
		if ips, err := ExpandIPRange(s, 10000); err != nil || len(ips) == 0 {
			t.Errorf("%s: %v", s, err)
		}
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
