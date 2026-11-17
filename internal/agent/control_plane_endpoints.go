package agent

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync/atomic"
	"time"

	wafebpf "github.com/wafio/wafio-agent-host/internal/ebpf"
	"github.com/wafio/wafio-cp-backend/shared/agentcore"
	"google.golang.org/grpc"
)

// Control-plane pass-through: before every dial the host agent hands
// the resolved control-plane address:port to the dataplane, which then never
// cuts that connection — egress Deny All, egress/ingress blocklists and the
// ingress default deny included (inbound only for replies of the agent's own
// flow).

var cpMapMissingLogged atomic.Bool

// pinnedCPEndpoints are the endpoints last written to wafio_cp_endpoints.
// The stream dials exactly these: gRPC's own resolver would
// need DNS, which egress Deny All may block, and round-robin DNS may hand
// it an address the dataplane does not pass.
var pinnedCPEndpoints atomic.Pointer[[]netip.AddrPort]

// cpEndpointSetter is the slice of *wafebpf.Manager used here.
type cpEndpointSetter interface {
	SetControlPlaneEndpoints([]netip.AddrPort) error
}

// refreshControlPlaneEndpoints resolves the control plane, writes it to the
// dataplane and returns the endpoints now in the map: the new ones, or the
// previous ones when resolution or the write failed. Nil when the dataplane
// has no pass-through (no manager, objects without the map).
func refreshControlPlaneEndpoints(ctx context.Context, serverAddr string) []netip.AddrPort {
	ebpfGRPCMu.Lock()
	mgr := ebpfGRPCEBPFMgr
	ebpfGRPCMu.Unlock()
	if mgr == nil {
		return nil
	}
	return refreshPinnedEndpoints(ctx, serverAddr, mgr, net.DefaultResolver.LookupNetIP)
}

func refreshPinnedEndpoints(ctx context.Context, serverAddr string, mgr cpEndpointSetter, lookup agentcore.LookupNetIPFunc) []netip.AddrPort {
	previous := func() []netip.AddrPort {
		if p := pinnedCPEndpoints.Load(); p != nil {
			return *p
		}
		return nil
	}
	endpoints, err := agentcore.ResolveControlPlaneEndpoints(ctx, serverAddr, lookup)
	if err != nil {
		log.Printf("[ebpf-grpc] control-plane pass-through not refreshed (keeping previous): %v", err)
		return previous()
	}
	if err := mgr.SetControlPlaneEndpoints(endpoints); err != nil {
		if errors.Is(err, wafebpf.ErrNoControlPlaneMap) {
			if cpMapMissingLogged.CompareAndSwap(false, true) {
				log.Printf("[ebpf-grpc] control-plane pass-through unavailable: %v", err)
			}
			return nil
		}
		log.Printf("[ebpf-grpc] control-plane pass-through: %v", err)
		return previous()
	}
	changed := true
	if p := pinnedCPEndpoints.Load(); p != nil {
		changed = !slices.Equal(*p, endpoints)
	}
	pinnedCPEndpoints.Store(&endpoints)
	if changed {
		updateSavedControlPlane(endpoints)
	}
	return endpoints
}

// seedControlPlaneEndpoints writes endpoints saved with the last good policy
// into the dataplane when the control plane cannot be resolved at start.
// Returns the endpoints now pinned, or nil.
func seedControlPlaneEndpoints(eps []netip.AddrPort) []netip.AddrPort {
	if len(eps) == 0 {
		return nil
	}
	ebpfGRPCMu.Lock()
	mgr := ebpfGRPCEBPFMgr
	ebpfGRPCMu.Unlock()
	if mgr == nil {
		return nil
	}
	if err := mgr.SetControlPlaneEndpoints(eps); err != nil {
		log.Printf("[ebpf-grpc] saved control-plane endpoints not seeded: %v", err)
		return nil
	}
	pinnedCPEndpoints.Store(&eps)
	log.Printf("[ebpf-grpc] control-plane pass-through seeded from the saved policy: %v", eps)
	return eps
}

// controlPlaneDialTarget returns the gRPC target and dial options: with
// pinned endpoints, a passthrough target (no gRPC DNS resolution; the
// authority, and so TLS verification, still names the configured host) and
// a dialer that connects only to those endpoints.
func controlPlaneDialTarget(serverAddr string, pinned []netip.AddrPort) (string, []grpc.DialOption) {
	if len(pinned) == 0 {
		return serverAddr, nil
	}
	host, port, err := agentcore.SplitControlPlaneAddr(serverAddr)
	if err != nil {
		return serverAddr, nil
	}
	target := "passthrough:///" + net.JoinHostPort(host, strconv.Itoa(int(port)))
	return target, []grpc.DialOption{grpc.WithContextDialer(pinnedDialer(pinned))}
}

// pinnedDialer tries each endpoint in order, five seconds each.
func pinnedDialer(endpoints []netip.AddrPort) func(context.Context, string) (net.Conn, error) {
	eps := slices.Clone(endpoints)
	return func(ctx context.Context, _ string) (net.Conn, error) {
		var d net.Dialer
		var errs []error
		for _, ep := range eps {
			actx, cancel := context.WithTimeout(ctx, 5*time.Second)
			conn, err := d.DialContext(actx, "tcp", ep.String())
			cancel()
			if err == nil {
				return conn, nil
			}
			errs = append(errs, err)
			if ctx.Err() != nil {
				break
			}
		}
		return nil, fmt.Errorf("control plane unreachable on pinned endpoints: %w", errors.Join(errs...))
	}
}
