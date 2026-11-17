package ebpf

import (
	"fmt"
	"net/netip"
	"strings"
)

// ExpandIPRange rejects inputs that cannot be represented in full within limit.
// Wildcards remain family-specific CIDRs for the kernel sentinel representation.
func ExpandIPRange(s string, limit int) ([]string, error) {
	s = strings.TrimSpace(s)
	if limit < 1 {
		return nil, fmt.Errorf("IP map capacity exhausted")
	}
	if s == "0.0.0.0/0" || s == "::/0" {
		return []string{s}, nil
	}
	var first, last netip.Addr
	if left, right, ok := strings.Cut(s, "-"); ok {
		var err error
		first, err = netip.ParseAddr(strings.TrimSpace(left))
		if err != nil {
			return nil, err
		}
		last, err = netip.ParseAddr(strings.TrimSpace(right))
		if err != nil {
			return nil, err
		}
		if !first.Is4() || !last.Is4() || first.Compare(last) > 0 {
			return nil, fmt.Errorf("unsupported or reversed IP range")
		}
	} else if strings.Contains(s, "/") {
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		prefix = prefix.Masked()
		bits := prefix.Addr().BitLen() - prefix.Bits()
		if bits >= 63 || uint64(1)<<bits > uint64(limit) {
			return nil, fmt.Errorf("IP prefix exceeds map capacity %d", limit)
		}
		out := make([]string, 0, 1<<bits)
		for ip := prefix.Addr(); ip.IsValid() && prefix.Contains(ip); ip = ip.Next() {
			out = append(out, ip.String())
		}
		return out, nil
	} else {
		ip, err := netip.ParseAddr(s)
		if err != nil || ip.Zone() != "" {
			return nil, fmt.Errorf("invalid IP address")
		}
		return []string{ip.String()}, nil
	}
	out := make([]string, 0)
	for ip := first; ip.IsValid() && ip.Compare(last) <= 0; ip = ip.Next() {
		if len(out) == limit {
			return nil, fmt.Errorf("IP range exceeds map capacity %d", limit)
		}
		out = append(out, ip.String())
	}
	return out, nil
}
