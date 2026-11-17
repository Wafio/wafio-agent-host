//go:build linux

package integration

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Ports of the CI peer (see README, "VM scenarios (CI)"). The peer runs on
// the GitHub runner, outside the VM; the VM reaches it through the QEMU
// user-mode gateway (usually 10.0.2.2), which slirp maps to the runner's
// 127.0.0.1.
const (
	vmPeerPort0 = 7000 // control-plane stand-in; also answers PROBE
	vmPeerPort1 = 7001 // an ordinary outbound service
	vmPeerDNS   = 53   // UDP echo
	vmProbePort = 7002 // TCP port the VM listens on, forwarded from the runner
)

// TestVMPeerServer is the runner-side half of the VM scenarios. It is not a
// test: it serves until SIGTERM (or 45 minutes) and only runs when the CI
// step sets WAFIO_VM_PEER_SERVE=1.
//
//	PING n     -> PONG n
//	PROBE port -> "PROBE ok" when a connection to 127.0.0.1:port (the runner
//	              side of the QEMU port forward into the VM) echoes within
//	              1.5 s, else "PROBE fail"
//
// UDP 127.0.0.1:53 echoes every datagram. It is bound to that address
// explicitly: systemd-resolved holds 127.0.0.53.
func TestVMPeerServer(t *testing.T) {
	if os.Getenv("WAFIO_VM_PEER_SERVE") != "1" {
		t.Skip("CI peer only (WAFIO_VM_PEER_SERVE=1)")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 45*time.Minute)
	defer cancel()

	var lc net.ListenConfig
	for _, port := range []int{vmPeerPort0, vmPeerPort1} {
		ln, err := lc.Listen(ctx, "tcp4", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go peerAccept(ctx, ln)
	}
	pc, err := lc.ListenPacket(ctx, "udp4", fmt.Sprintf("127.0.0.1:%d", vmPeerDNS))
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go peerEchoUDP(pc)

	// Goroutines outside the test must not use t after it returns, so the
	// peer logs to stderr (build/vm-peer.log).
	fmt.Fprintln(os.Stderr, "vm-peer: serving 127.0.0.1:7000, 7001 (tcp) and 53 (udp)")
	<-ctx.Done()
	fmt.Fprintln(os.Stderr, "vm-peer: stopping")
}

func peerAccept(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go peerServe(ctx, conn)
	}
}

func peerServe(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		var reply string
		switch fields[0] {
		case "PING":
			reply = "PONG " + fields[1] + "\n"
		case "PROBE":
			reply = "PROBE fail\n"
			if peerProbe(ctx, fields[1]) {
				reply = "PROBE ok\n"
			}
		default:
			continue
		}
		if _, err := conn.Write([]byte(reply)); err != nil {
			return
		}
	}
}

// peerProbe dials the forwarded port on the runner's loopback and waits for
// the echo from the VM listener.
func peerProbe(ctx context.Context, port string) bool {
	deadline := time.Now().Add(1500 * time.Millisecond)
	dctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dctx, "tcp4", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		return false
	}
	defer conn.Close()
	// Close with a reset: the probe needs no orderly teardown, and a
	// lingering forwarded socket is a descriptor in the QEMU process.
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write([]byte("hi\n")); err != nil {
		return false
	}
	buf := make([]byte, 3)
	n := 0
	for n < len(buf) {
		m, err := conn.Read(buf[n:])
		n += m
		if err != nil {
			break
		}
	}
	return string(buf[:n]) == "hi\n"
}

func peerEchoUDP(pc net.PacketConn) {
	buf := make([]byte, 512)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = pc.WriteTo(buf[:n], from)
	}
}
