package ebpf

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

// CPEndpointKey must match struct cp_endpoint_key byte for byte: the XDP and
// TC lookups key on the wire-order port.
func TestCPEndpointKeyLayout(t *testing.T) {
	encode := func(ap string) []byte {
		var buf bytes.Buffer
		if err := binary.Write(&buf, binary.NativeEndian, CPEndpointKeyFrom(netip.MustParseAddrPort(ap))); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	b := encode("203.0.113.9:9090")
	if len(b) != 24 || b[0] != 2 || !bytes.Equal(b[4:8], []byte{203, 0, 113, 9}) ||
		!bytes.Equal(b[20:22], []byte{0x23, 0x82}) || b[22] != 6 || b[23] != 0 {
		t.Fatalf("layout % x", b)
	}
	if !bytes.Equal(encode("[::ffff:203.0.113.9]:9090"), b) {
		t.Fatal("v4-mapped control-plane address must key as IPv4 (the packet is IPv4)")
	}
	if b := encode("[2001:db8::9]:443"); b[0] != 10 || b[4] != 0x20 || b[5] != 0x01 || !bytes.Equal(b[20:22], []byte{0x01, 0xbb}) {
		t.Fatalf("v6 layout % x", b)
	}
}

// The default configuration a cleared desired state delivers equals
// what a freshly started agent writes (writeDefaultConfig uses it).
func TestDefaultFullConfigAPI(t *testing.T) {
	def := DefaultFullConfigAPI()
	var g GlobalConfig
	g.FromAPI(def.Global)
	if g.Enabled != 1 || g.Mode != 1 || g.EnableConntrack != 1 || g.LogBlocked != 1 || g.EnableGeoblock != 0 {
		t.Fatalf("global %+v", g)
	}
	var r RateConfig
	r.FromAPI(def.Rate)
	if r.WindowNs != 1_000_000_000 || r.MaxPPS != 10000 || r.Action != 2 || r.SynPressurePPS != 50000 {
		t.Fatalf("rate %+v", r)
	}
	if err := ValidateRateConfig(def.Rate); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePortScanConfig(def.PortScan); err != nil {
		t.Fatal(err)
	}
}
