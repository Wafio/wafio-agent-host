package ebpf

import (
	"fmt"
	"os"
	"slices"
	"strings"
)

// kernelLSMListPath names the security modules the running kernel calls,
// comma separated ("lockdown,capability,apparmor,bpf"). The kernel accepts a
// BPF-LSM attach whether or not bpf is in this list, but it calls the
// programs only when it is.
const kernelLSMListPath = "/sys/kernel/security/lsm"

// Values of TraceStatus.LSMState.
const (
	// LSMStateActive: bpf is in the kernel's LSM list and the programs are attached.
	LSMStateActive = "active"
	// LSMStateKernelLacksBPF: bpf is not in the kernel's LSM list (boot
	// parameter lsm=...,bpf), so the programs are not attached.
	LSMStateKernelLacksBPF = "kernel_lacks_bpf"
	// LSMStateUnverified: the programs are attached but the kernel's LSM list
	// could not be read, so whether the kernel calls them is unknown.
	LSMStateUnverified = "unverified"
	// LSMStateDisabled: switched off with --lsm=false.
	LSMStateDisabled = "disabled"
	// LSMStateFailed: the LSM object could not be loaded or attached.
	LSMStateFailed = "failed"
)

// lsmPlan is what the agent does about BPF-LSM at start.
type lsmPlan struct {
	Attach bool
	// State is the LSMState to report: why nothing is attached, or the state
	// the attached programs are in (LSMStateFailed replaces it when the load
	// then fails).
	State string
	// Note is the reason to log: why nothing is attached, or that the kernel's
	// state is unknown. Empty when there is nothing to say.
	Note string
}

// parseKernelLSMList splits the content of kernelLSMListPath.
func parseKernelLSMList(data string) []string {
	var out []string
	for _, name := range strings.Split(data, ",") {
		if name = strings.TrimSpace(name); name != "" {
			out = append(out, name)
		}
	}
	return out
}

// decideLSM decides from the content of the kernel's LSM list (data, or the
// error from reading it) whether to attach the LSM programs.
func decideLSM(enabled bool, data string, readErr error) lsmPlan {
	switch {
	case !enabled:
		return lsmPlan{State: LSMStateDisabled}
	case readErr != nil:
		return lsmPlan{Attach: true, State: LSMStateUnverified,
			Note: fmt.Sprintf("cannot read the kernel LSM list (%v), so whether the kernel runs BPF-LSM is unknown; attaching the LSM programs anyway", readErr)}
	}
	lsms := parseKernelLSMList(data)
	if !slices.Contains(lsms, "bpf") {
		active := strings.Join(lsms, ",")
		if active == "" {
			active = "none"
		}
		return lsmPlan{State: LSMStateKernelLacksBPF,
			Note: fmt.Sprintf("BPF-LSM is not active in this kernel (active LSMs: %s; boot parameter lsm=...,bpf needed), so the LSM programs are not attached", active)}
	}
	return lsmPlan{Attach: true, State: LSMStateActive}
}

// planLSM reads the kernel's LSM list from path and decides.
func planLSM(enabled bool, path string) lsmPlan {
	if !enabled {
		return decideLSM(false, "", nil)
	}
	data, err := os.ReadFile(path)
	return decideLSM(true, string(data), err)
}
