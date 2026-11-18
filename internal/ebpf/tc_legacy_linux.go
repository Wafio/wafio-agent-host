//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const legacyTCPriority = 1

type legacyTCFilter struct {
	filter *netlink.BpfFilter
	progID int
}

type legacyTCAttachment struct {
	ifIndex    int
	ownedQdisc bool
	ingress    *legacyTCFilter
	egress     *legacyTCFilter
	logf       func(format string, args ...any) // nil: no log
}

func (a *legacyTCAttachment) attach(parent uint32, prog *ebpf.Program) error {
	iface, err := netlink.LinkByIndex(a.ifIndex)
	if err != nil {
		return fmt.Errorf("find interface: %w", err)
	}
	if err := a.ensureClsact(iface); err != nil {
		return err
	}
	info, err := prog.Info()
	if err != nil {
		return fmt.Errorf("read TC program ID: %w", err)
	}
	id, ok := info.ID()
	if !ok {
		return fmt.Errorf("TC program ID unavailable")
	}
	name, handle := "wafio_ingress", uint32(0x57414649)
	if parent == netlink.HANDLE_MIN_EGRESS {
		name, handle = "wafio_egress", 0x5741464a
	}
	f := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: a.ifIndex,
			Parent:    parent,
			Handle:    handle,
			Priority:  legacyTCPriority,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           prog.FD(),
		Name:         name,
		DirectAction: true,
	}
	a.removeStaleFilters(iface, parent, handle)
	if err := netlink.FilterAdd(f); err != nil {
		return fmt.Errorf("add %s filter: %w", name, err)
	}
	owned := &legacyTCFilter{filter: f, progID: int(id)}
	if parent == netlink.HANDLE_MIN_INGRESS {
		a.ingress = owned
	} else {
		a.egress = owned
	}
	if !a.attached(parent) {
		return fmt.Errorf("%s filter not visible after attach", name)
	}
	return nil
}

// removeStaleFilters deletes the filters of an agent that was killed before it
// detached: on this parent, with our handle and a name that starts with
// "wafio_". The kernel keeps a legacy filter after its process ends, and a
// second filter with the same handle makes FilterAdd fail, so the new run
// would start without TC. A failure is logged; FilterAdd then reports it.
func (a *legacyTCAttachment) removeStaleFilters(iface netlink.Link, parent, handle uint32) {
	filters, err := netlink.FilterList(iface, parent)
	if err != nil {
		return
	}
	for _, candidate := range filters {
		f, ok := candidate.(*netlink.BpfFilter)
		if !ok || f.Handle != handle || !strings.HasPrefix(f.Name, "wafio_") {
			continue
		}
		if err := netlink.FilterDel(f); err != nil {
			a.log("remove stale TC filter %s: %v", f.Name, err)
			continue
		}
		a.log("removed stale TC filter %s left by a run that did not detach", f.Name)
	}
}

func (a *legacyTCAttachment) log(format string, args ...any) {
	if a.logf != nil {
		a.logf(format, args...)
	}
}

func (a *legacyTCAttachment) ensureClsact(iface netlink.Link) error {
	qdiscs, err := netlink.QdiscList(iface)
	if err != nil {
		return fmt.Errorf("list qdiscs: %w", err)
	}
	for _, q := range qdiscs {
		if q.Attrs().Parent == netlink.HANDLE_CLSACT {
			if q.Type() != "clsact" {
				return fmt.Errorf("existing ingress qdisc %q prevents clsact", q.Type())
			}
			return nil
		}
	}
	qdisc := &netlink.Clsact{QdiscAttrs: netlink.QdiscAttrs{
		LinkIndex: a.ifIndex,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		return fmt.Errorf("add clsact: %w", err)
	}
	a.ownedQdisc = true
	return nil
}

func (a *legacyTCAttachment) attached(parent uint32) bool {
	owned := a.ingress
	if parent == netlink.HANDLE_MIN_EGRESS {
		owned = a.egress
	}
	if owned == nil {
		return false
	}
	_, ok := a.findOwnFilter(parent, owned)
	return ok
}

func (a *legacyTCAttachment) findOwnFilter(parent uint32, owned *legacyTCFilter) (*netlink.BpfFilter, bool) {
	iface, err := netlink.LinkByIndex(a.ifIndex)
	if err != nil {
		return nil, false
	}
	filters, err := netlink.FilterList(iface, parent)
	if err != nil {
		return nil, false
	}
	for _, candidate := range filters {
		f, ok := candidate.(*netlink.BpfFilter)
		if ok && f.Handle == owned.filter.Handle && f.Priority == owned.filter.Priority &&
			f.Name == owned.filter.Name && f.Id == owned.progID {
			return f, true
		}
	}
	return nil, false
}

func (a *legacyTCAttachment) close() error {
	var errs []error
	for _, hook := range []struct {
		parent uint32
		owned  *legacyTCFilter
	}{
		{netlink.HANDLE_MIN_INGRESS, a.ingress},
		{netlink.HANDLE_MIN_EGRESS, a.egress},
	} {
		if hook.owned == nil {
			continue
		}
		if f, ok := a.findOwnFilter(hook.parent, hook.owned); ok {
			if err := netlink.FilterDel(f); err != nil {
				errs = append(errs, fmt.Errorf("remove %s: %w", f.Name, err))
			}
		}
	}
	if !a.ownedQdisc {
		return errors.Join(errs...)
	}
	iface, err := netlink.LinkByIndex(a.ifIndex)
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	for _, parent := range []uint32{netlink.HANDLE_MIN_INGRESS, netlink.HANDLE_MIN_EGRESS} {
		filters, err := netlink.FilterList(iface, parent)
		if err != nil {
			return errors.Join(append(errs, err)...)
		}
		if len(filters) != 0 {
			return errors.Join(errs...)
		}
	}
	qdisc := &netlink.Clsact{QdiscAttrs: netlink.QdiscAttrs{
		LinkIndex: a.ifIndex,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}}
	if err := netlink.QdiscDel(qdisc); err != nil {
		errs = append(errs, fmt.Errorf("remove owned clsact: %w", err))
	}
	return errors.Join(errs...)
}
