package ebpf

import "strings"

// LSM file_open variants. wafio_lsm.o carries two programs for the hook:
// lsmProgFileOpen resolves the full path with bpf_d_path, and
// lsmProgFileOpenBasename matches the file name alone. Kernel 5.10 refuses
// bpf_d_path in the file_open hook ("helper call is not allowed in probe"),
// and one rejected program fails the whole collection, so the loader tries the
// full variant first and falls back to the basename one, but only for that
// specific verifier error; connect, sendmsg and exec hooks load either way.
const (
	lsmProgFileOpen         = "wafio_file_open"
	lsmProgFileOpenBasename = "wafio_file_open_basename"
)

// Values of TraceStatus.LSMFileOpen.
const (
	// LSMFileOpenDPath: file_open denies by full path (bpf_d_path).
	LSMFileOpenDPath = "dpath"
	// LSMFileOpenBasename: the kernel has no usable bpf_d_path for this hook
	// (5.8 and 5.9 lack the helper, 5.10 refuses it in LSM programs);
	// file_open looks up the dentry name ("shadow"). The blocklist keys are
	// absolute paths, so such an entry never matches in this mode: only a
	// bare file-name key would.
	LSMFileOpenBasename = "basename"
	// LSMFileOpenNone: no file_open program is loaded (object without one,
	// or the variant(s) rejected).
	LSMFileOpenNone = "none"
)

// createLSMCollection loads the LSM object's programs with createDroppingOptional
// semantics (socket_sendmsg and file_open are optional) and picks exactly one file_open
// variant: the full one, or, when the verifier refuses bpf_d_path for the
// hook, the basename one. A full variant rejected for any other reason stays
// dropped (variant none; the error is in dropped).
// create must read the programs map. closeColl releases a collection that is
// replaced. variant is one of the LSMFileOpen* values; dropped maps each
// removed program to its error (a rejected full variant included).
func createLSMCollection[P, C any](programs map[string]P, create func() (C, error), closeColl func(C)) (coll C, dropped map[string]error, variant string, err error) {
	// The basename variant is held back only while the full one is there to
	// try first; an object with the basename variant alone loads it directly.
	fallback, hasFallback := programs[lsmProgFileOpenBasename]
	_, hasFull := programs[lsmProgFileOpen]
	hasFallback = hasFallback && hasFull
	if hasFallback {
		delete(programs, lsmProgFileOpenBasename)
	}
	coll, dropped, err = createDroppingOptional(programs, []string{lsmProgSendmsg, lsmProgFileOpen, lsmProgFileOpenBasename}, create)
	if err != nil {
		return coll, dropped, LSMFileOpenNone, err
	}
	if why, rejected := dropped[lsmProgFileOpen]; !rejected || !hasFallback || !refusesDPath(why) {
		// Accepted, no fallback in the object, or rejected for another reason.
		return coll, dropped, lsmVariant(programs), nil
	}

	// The verifier refused bpf_d_path: reload with the basename variant in
	// its place.
	closeColl(coll)
	programs[lsmProgFileOpenBasename] = fallback
	coll, again, err := createDroppingOptional(programs, []string{lsmProgSendmsg, lsmProgFileOpenBasename}, create)
	for name, why := range again {
		dropped[name] = why
	}
	if err != nil {
		// The reload failed (transient map or verifier error): keep the
		// hooks that had loaded without file_open rather than losing the
		// whole LSM.
		delete(programs, lsmProgFileOpenBasename)
		dropped[lsmProgFileOpenBasename] = err
		coll, again, err = createDroppingOptional(programs, []string{lsmProgSendmsg}, create)
		for name, why := range again {
			dropped[name] = why
		}
		if err != nil {
			return coll, dropped, LSMFileOpenNone, err
		}
	}
	return coll, dropped, lsmVariant(programs), nil
}

// refusesDPath reports whether err is the verifier refusing bpf_d_path for the
// file_open hook: it names the full variant and carries the helper message.
func refusesDPath(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "program "+lsmProgFileOpen+":") &&
		strings.Contains(msg, "helper call is not allowed")
}

// reportedFileOpenVariant is the variant the status shows: the full program
// only counts as "dpath" when the kernel BTF really has BPF_FUNC_d_path; on
// 5.8/5.9 the CO-RE guard in the program takes the basename branch even
// though the full variant loaded.
func reportedFileOpenVariant(variant string, kernelHasDPath bool) string {
	if variant == LSMFileOpenDPath && !kernelHasDPath {
		return LSMFileOpenBasename
	}
	return variant
}

// lsmVariant names the file_open variant left in programs.
func lsmVariant[P any](programs map[string]P) string {
	if _, ok := programs[lsmProgFileOpen]; ok {
		return LSMFileOpenDPath
	}
	if _, ok := programs[lsmProgFileOpenBasename]; ok {
		return LSMFileOpenBasename
	}
	return LSMFileOpenNone
}
