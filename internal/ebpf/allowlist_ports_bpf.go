package ebpf

// Port-scoped allowlist entries. An allowlist entry without ports passes every
// packet of its source, every port and protocol (ICMP included) — the
// behaviour of every earlier version. An entry with ports passes only TCP/UDP
// packets whose destination port lies in one of its scopes; the rest of the
// source's traffic meets the normal path (blocklist, jail, geo, port rules,
// rate limits). The dataplane matches the scopes in wafio_xdp.c
// (allow_scope_hit); objects that cannot are detected by the marker map
// wafio_allow_scopes and refuse scoped entries.

// allowValScopes encodes normalised scopes into an allow_val: no scopes =
// ALLOW_F_ALL (every port and protocol).
func allowValScopes(v *AllowVal, ports []PortScope) error {
	norm, err := NormalizePortScopes(ports)
	if err != nil {
		return err
	}
	v.Scopes = [allowMaxScopes]AllowScope{}
	if len(norm) == 0 {
		v.Flags, v.NScopes = AllowFlagAll, 0
		return nil
	}
	v.Flags = 0
	v.NScopes = u32FromInt(len(norm))
	for i, p := range norm {
		var proto uint8
		switch p.Proto {
		case PortProtoTCP:
			proto = protoTCP
		case PortProtoUDP:
			proto = protoUDP
		}
		v.Scopes[i] = AllowScope{Lo: u16FromInt(p.From), Hi: u16FromInt(p.To), Proto: proto}
	}
	return nil
}

// portProtoNone marks a live allowlist value that allows no packet (no
// ALLOW_F_ALL and no usable scope; this agent never writes one). It fails
// NormalizePortScopes, so the local lockout check refuses to judge a state
// holding it and a push rewrites it (its ports differ from any desired).
const portProtoNone = "none"

// portScopesOfAllowVal decodes the scopes of an allow_val (nil = every
// port).
func portScopesOfAllowVal(v AllowVal) []PortScope {
	if v.Flags&AllowFlagAll != 0 {
		return nil
	}
	n := min(int(v.NScopes), allowMaxScopes)
	out := make([]PortScope, 0, n)
	for _, s := range v.Scopes[:n] {
		proto := PortProtoAny
		switch s.Proto {
		case protoTCP:
			proto = PortProtoTCP
		case protoUDP:
			proto = PortProtoUDP
		case protoAny:
		default:
			continue // matches no packet
		}
		out = append(out, PortScope{Proto: proto, From: int(s.Lo), To: int(s.Hi)})
	}
	if len(out) == 0 {
		return []PortScope{{Proto: portProtoNone}}
	}
	return out
}
