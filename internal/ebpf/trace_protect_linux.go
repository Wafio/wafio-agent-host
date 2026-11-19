//go:build linux

package ebpf

import "os"

// runProtectedSelfCheck performs the first protected-set sync synchronously
// (without the kernel map: one /proc scan, for the count) and reports what it
// found. It touches state owned by protectedRefreshLoop, so it must run before
// that loop starts.
func (tm *TraceManager) runProtectedSelfCheck() protectedSelfCheck {
	c := protectedSelfCheck{
		kernelSet:  tm.protectedMap != nil,
		risky:      tm.protected.RiskyEntries(),
		procDenied: procIdentityDenied(tm.proc()),
	}
	if tm.protectedMap == nil {
		tgids, err := tm.protected.scanProtectedTGIDs(tm.proc(), os.Getpid())
		c.matched, c.scanErr = len(tgids), err
		return c
	}
	c.valueSize = tm.protectedMap.ValueSize()
	c.matched, c.scanErr = tm.syncProtectedTGIDs()
	c.kernelTGIDs = len(tm.protectedTGIDs)
	return c
}
