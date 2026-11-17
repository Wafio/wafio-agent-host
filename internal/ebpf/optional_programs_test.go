package ebpf

import (
	"errors"
	"fmt"
	"slices"
	"testing"
)

// A rejected optional hook (sendmsg, legacy syscalls) must not
// take the rest of its object down, nor the other optional hooks: the
// program the load error names is removed and the load retried, one program
// at a time; only an unidentifiable failure drops every optional program.
func TestCreateDroppingOptional(t *testing.T) {
	rejectedBy := func(bad ...string) func(progs map[string]int) (int, error) {
		return func(progs map[string]int) (int, error) {
			for _, name := range bad {
				if _, ok := progs[name]; ok {
					return 0, fmt.Errorf("program %s: load program: permission denied", name)
				}
			}
			return len(progs), nil
		}
	}
	run := func(progs map[string]int, optional []string, load func(map[string]int) (int, error)) (int, map[string]error, error) {
		return createDroppingOptional(progs, optional, func() (int, error) { return load(progs) })
	}
	t.Run("clean load keeps everything", func(t *testing.T) {
		progs := map[string]int{"core": 1, "opt": 2}
		coll, dropped, err := run(progs, []string{"opt"}, rejectedBy())
		if err != nil || len(dropped) != 0 || coll != 2 {
			t.Fatalf("coll=%d dropped=%v err=%v", coll, dropped, err)
		}
	})
	t.Run("only the rejected programs go", func(t *testing.T) {
		progs := map[string]int{"core": 1, "open": 2, "openat2": 3, "chmod": 4, "unlink": 5}
		coll, dropped, err := run(progs, []string{"open", "openat2", "chmod", "unlink"}, rejectedBy("openat2", "chmod"))
		if err != nil || coll != 3 || !slices.Equal(droppedNames(dropped), []string{"chmod", "openat2"}) {
			t.Fatalf("coll=%d dropped=%v err=%v", coll, droppedNames(dropped), err)
		}
		if _, ok := progs["open"]; !ok {
			t.Fatal("an accepted optional program was dropped")
		}
	})
	t.Run("name prefix does not match another program", func(t *testing.T) {
		progs := map[string]int{"core": 1, "trace_open": 2, "trace_openat2": 3}
		_, dropped, err := run(progs, []string{"trace_open", "trace_openat2"}, rejectedBy("trace_openat2"))
		if err != nil || !slices.Equal(droppedNames(dropped), []string{"trace_openat2"}) {
			t.Fatalf("dropped=%v err=%v", droppedNames(dropped), err)
		}
	})
	t.Run("unidentified failure drops the optional programs once", func(t *testing.T) {
		progs := map[string]int{"core": 1, "a": 2, "b": 3}
		calls := 0
		coll, dropped, err := run(progs, []string{"a", "b"}, func(p map[string]int) (int, error) {
			calls++
			if _, ok := p["a"]; ok {
				return 0, errors.New("map trace_scratch: out of memory")
			}
			return len(p), nil
		})
		if err != nil || coll != 1 || calls != 2 || !slices.Equal(droppedNames(dropped), []string{"a", "b"}) {
			t.Fatalf("coll=%d calls=%d dropped=%v err=%v", coll, calls, droppedNames(dropped), err)
		}
	})
	t.Run("a failing core program still fails", func(t *testing.T) {
		progs := map[string]int{"core": 1, "opt": 2}
		coll, _, err := run(progs, []string{"opt"}, rejectedBy("core"))
		if err == nil || coll != 0 {
			t.Fatalf("coll=%d err=%v", coll, err)
		}
	})
}

// droppedNames lists the programs createDroppingOptional removed, sorted.
func droppedNames(dropped map[string]error) []string {
	names := make([]string, 0, len(dropped))
	for name := range dropped {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}
