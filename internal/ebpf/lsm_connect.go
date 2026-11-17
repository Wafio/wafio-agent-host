package ebpf

import (
	"net/netip"
	"slices"
	"strings"
)

// afInet6 is AF_INET6 as the trace and LSM programs store it.
const afInet6 uint16 = 10

// lsmMapConnectV4Mapped is the ABI marker in wafio_lsm.o: its
// socket_connect hook checks IPv4-mapped AF_INET6 destinations against the
// IPv4 blocklist. Older objects lack it and return early for AF_INET6.
const lsmMapConnectV4Mapped = "wafio_lsm_connect_v4mapped"

// lsmProgSendmsg is the socket_sendmsg program. Optional:
// an object without it, a kernel without the hook, or a verifier that
// rejects it leaves addressed sends enforced from userspace.
const lsmProgSendmsg = "wafio_socket_sendmsg"

// SetConnectBlocklistIPv4Mapped records whether the loaded LSM object's
// socket_connect hook also denies an AF_INET6 connect to the IPv4-mapped
// form of a blocklisted address. Only then may Evaluate skip its own
// action on such a connect; with an older object userspace still enforces it.
func (pe *PolicyEngine) SetConnectBlocklistIPv4Mapped(covered bool) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.connectMapped = covered
	pe.syncKillRoutingLocked()
}

// connectHookCoversEvent reports whether the BPF-LSM socket_connect hook
// checked this traced connect's destination against the IPv4 blocklist: an
// AF_INET connect always, an AF_INET6 connect to an IPv4-mapped address
// (::ffff:a.b.c.d, rendered dotted by the trace decoder) only with an object
// that has the marker (mapped). sendto and every other event never pass the hook.
func connectHookCoversEvent(evt TraceEvent, mapped bool) bool {
	if !strings.EqualFold(evt.EventName, "connect") {
		return false
	}
	return ipv4Destination(evt, mapped)
}

// sendHookCoversEvent reports whether the BPF-LSM socket_sendmsg hook
// checked this traced sendto's destination against the IPv4
// blocklist: an AF_INET destination, or an AF_INET6 one carrying an
// IPv4-mapped address — the hook reads both from its first version.
func sendHookCoversEvent(evt TraceEvent) bool {
	if !strings.EqualFold(evt.EventName, "sendto") {
		return false
	}
	return ipv4Destination(evt, true)
}

// ipv4Destination: the event names an IPv4 peer the blocklist can hold — an
// AF_INET destination, or (mapped) an IPv4-mapped AF_INET6 one.
func ipv4Destination(evt TraceEvent, mapped bool) bool {
	switch evt.AddrFamily {
	case afInet:
		return true
	case afInet6:
		if !mapped {
			return false
		}
		a, err := netip.ParseAddr(evt.Addr)
		return err == nil && (a.Is4() || a.Is4In6())
	}
	return false
}

// policySelectsSend reports whether a dest-IP policy selects sendto events:
// no event types (all) or sendto among them. Only then does its connect
// blocklist entry carry LSMRuleSend, so the socket_sendmsg hook never denies
// a send the policy does not select.
func policySelectsSend(p *EnforcementPolicy) bool {
	return len(p.EventTypes) == 0 || slices.ContainsFunc(p.EventTypes, func(name string) bool {
		return strings.EqualFold(name, "sendto")
	})
}

// lsmConnectFamily returns the socket family an object with the family field
// reports for a blocked connect or addressed send, and a note for the event
// description when it came from an IPv6 socket. Older objects leave the field
// unset (stale ring bytes): anything but AF_INET/AF_INET6 is ignored.
func lsmConnectFamily(evt WafioLSMEvent) (uint16, string) {
	if evt.Hook != LSMHookConnect && evt.Hook != LSMHookSendmsg {
		return 0, ""
	}
	switch evt.Family {
	case afInet:
		return afInet, ""
	case afInet6:
		return afInet6, " (IPv4-mapped IPv6)"
	}
	return 0, ""
}
