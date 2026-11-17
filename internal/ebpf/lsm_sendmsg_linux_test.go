//go:build linux

package ebpf

import (
	"errors"
	"syscall"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// TestKernelLSMSendmsgDeniesAddressedSends attaches wafio_socket_sendmsg
// with private maps and checks, on the running kernel, that an
// addressed send to a blocklisted IPv4 address fails with EPERM — unconnected
// UDP sendto, AF_UNSPEC on an AF_INET socket, an IPv4-mapped AF_INET6
// destination and a TCP Fast Open send — while an entry without
// LSM_RULE_SEND and a send on a connected socket are not denied here. Only
// TEST-NET-3 addresses are listed. Needs root, BPF LSM (lsm=...,bpf) and
// WAFIO_TEST_BPF_DIR: kernel lab.
func TestKernelLSMSendmsgDeniesAddressedSends(t *testing.T) {
	c := packetObjectCollection(t, "wafio_lsm.o")
	if planLSM(true, kernelLSMListPath).State != LSMStateActive {
		t.Skip("BPF LSM not enabled on this kernel")
	}
	prog := c.Programs[lsmProgSendmsg]
	if prog == nil {
		t.Fatalf("wafio_lsm.o lacks %s", lsmProgSendmsg)
	}
	blocked := [4]byte{203, 0, 113, 9}
	flagless := [4]byte{203, 0, 113, 10}
	putPacketMap(t, c, lsmMapConfig, uint32(0), LSMConfig{Enabled: 1, BlockConnect: 1})
	putPacketMap(t, c, lsmMapIPBlocklist, blocked, LSMRule{Action: ActionBlock, PolicyID: 7, Enabled: 1, Flags: LSMRuleSend})
	putPacketMap(t, c, lsmMapIPBlocklist, flagless, LSMRule{Action: ActionBlock, PolicyID: 8, Enabled: 1})
	l, err := link.AttachLSM(link.LSMOptions{Program: prog})
	if err != nil {
		t.Fatalf("%+v", err)
	}
	defer l.Close()

	sock := func(t *testing.T, family, typ int) int {
		t.Helper()
		fd, err := unix.Socket(family, typ|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = unix.Close(fd) })
		return fd
	}
	to4 := func(ip [4]byte) *unix.SockaddrInet4 { return &unix.SockaddrInet4{Port: 9, Addr: ip} }
	payload := []byte("x")

	if err := unix.Sendto(sock(t, unix.AF_INET, unix.SOCK_DGRAM), payload, 0, to4(blocked)); !errors.Is(err, unix.EPERM) {
		t.Errorf("UDP sendto a blocklisted address: %v, want EPERM", err)
	}
	if err := unix.Sendto(sock(t, unix.AF_INET, unix.SOCK_DGRAM), payload, 0, to4(flagless)); errors.Is(err, unix.EPERM) {
		t.Errorf("entry without LSM_RULE_SEND denied a send")
	}

	// AF_UNSPEC: udp_sendmsg reads sin_addr as if it were AF_INET.
	fd := sock(t, unix.AF_INET, unix.SOCK_DGRAM)
	raw := unix.RawSockaddrInet4{Family: unix.AF_UNSPEC, Port: 9 << 8, Addr: blocked}
	_, _, errno := unix.Syscall6(unix.SYS_SENDTO, uintptr(fd), uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)),
		0, uintptr(unsafe.Pointer(&raw)), unsafe.Sizeof(raw))
	if errno != syscall.EPERM {
		t.Errorf("AF_UNSPEC sendto on an AF_INET socket: %v, want EPERM", errno)
	}

	mapped := [16]byte{10: 0xff, 11: 0xff, 12: 203, 13: 0, 14: 113, 15: 9}
	if err := unix.Sendto(sock(t, unix.AF_INET6, unix.SOCK_DGRAM), payload, 0, &unix.SockaddrInet6{Port: 9, Addr: mapped}); !errors.Is(err, unix.EPERM) {
		t.Errorf("UDP sendto the IPv4-mapped form: %v, want EPERM", err)
	}

	// MSG_FASTOPEN connects inside tcp_sendmsg, never through socket_connect.
	if err := unix.Sendto(sock(t, unix.AF_INET, unix.SOCK_STREAM), payload, unix.MSG_FASTOPEN, to4(blocked)); !errors.Is(err, unix.EPERM) {
		t.Errorf("TCP Fast Open send: %v, want EPERM", err)
	}

	// A connected socket's send names no destination: this hook leaves it
	// to socket_connect (not attached here).
	fd = sock(t, unix.AF_INET, unix.SOCK_DGRAM)
	if err := unix.Connect(fd, to4(blocked)); err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := unix.Write(fd, payload); errors.Is(err, unix.EPERM) {
		t.Errorf("send on a connected socket denied by socket_sendmsg")
	}
}
