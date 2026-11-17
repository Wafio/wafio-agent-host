package ebpf

import (
	"slices"
	"strings"
	"testing"
)

func TestParseListenPorts(t *testing.T) {
	const tcp = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1111 1 0000000000000000 100 0 0 10 0
   1: 00000000:08AE 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2222 1 0000000000000000 100 0 0 10 0
   2: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 3333 1 0000000000000000 100 0 0 10 0
   3: 0A00000A:0016 0B00000A:D431 01 00000000:00000000 02:00000000 00000000     0        0 1111 1 0000000000000000 20 4 30 10 -1
   4: garbage
`
	ports := parseListenPorts(strings.NewReader(tcp), map[uint64]bool{1111: true, 2222: true})
	if !slices.Equal(sortedUniquePorts(ports), []uint16{22, 2222}) {
		t.Fatalf("ports %v", ports)
	}
	if got := sortedUniquePorts([]uint16{22, 2222, 22}); !slices.Equal(got, []uint16{22, 2222}) {
		t.Fatalf("dedupe %v", got)
	}
	if sortedUniquePorts(nil) != nil {
		t.Fatal("empty input must stay nil (guard falls back to 22)")
	}
	for link, want := range map[string]uint64{"socket:[4242]": 4242, "pipe:[1]": 0, "socket:[x]": 0, "socket:[12": 0} {
		got, ok := socketInode(link)
		if got != want || ok != (want != 0) {
			t.Fatalf("%q -> %d %v", link, got, ok)
		}
	}
}

func TestIsSSHDaemon(t *testing.T) {
	for _, tc := range []struct {
		comm, exe string
		want      bool
	}{
		{"sshd", "/usr/sbin/sshd", true},
		{"sshd", "/usr/sbin/sshd (deleted)", true},
		{"dropbear", "/usr/sbin/dropbear", true},
		{"sshd", "/tmp/evil", false},      // comm is settable by any process
		{"evil", "/usr/sbin/sshd", false}, // both must agree
		{"sshd-session", "/usr/lib/openssh/sshd-session", false},
	} {
		if got := isSSHDaemon(tc.comm, tc.exe); got != tc.want {
			t.Fatalf("%q %q -> %v", tc.comm, tc.exe, got)
		}
	}
}
