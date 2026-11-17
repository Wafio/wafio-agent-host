package ebpf

import (
	"slices"
	"strings"
)

// createDroppingOptional runs create; while it fails naming one of the
// optional programs ("program <name>: …", as cilium/ebpf reports a program
// that failed to load), that program is deleted from programs (the spec's
// program map, which create reads) and create runs again, so a kernel that
// rejects one new hook keeps every other program, optional or not. A failure
// that names no remaining optional program drops all remaining optional
// programs once (the failing one may still be among them); a failure after
// that is returned. Hooks added after the objects were last verifier-checked
// on a real kernel are optional this way. dropped maps each removed program
// to the error that removed it; err is nil when a collection was created.
func createDroppingOptional[P, C any](programs map[string]P, optional []string, create func() (C, error)) (coll C, dropped map[string]error, err error) {
	var remaining []string
	for _, name := range optional {
		if _, ok := programs[name]; ok && !slices.Contains(remaining, name) {
			remaining = append(remaining, name)
		}
	}
	for {
		coll, err = create()
		if err == nil {
			return coll, dropped, nil
		}
		if dropped == nil {
			dropped = make(map[string]error)
		}
		msg := err.Error()
		i := slices.IndexFunc(remaining, func(name string) bool {
			return strings.Contains(msg, "program "+name+":")
		})
		switch {
		case i >= 0:
			delete(programs, remaining[i])
			dropped[remaining[i]] = err
			remaining = slices.Delete(remaining, i, i+1)
		case len(remaining) > 0:
			for _, name := range remaining {
				delete(programs, name)
				dropped[name] = err
			}
			remaining = nil
		default:
			var zero C
			return zero, dropped, err
		}
	}
}
