package ebpf

import (
	"fmt"
	"slices"
	"testing"
)

// The LSM object carries two file_open programs; the loader must end up with
// exactly one: the full-path variant when the kernel accepts bpf_d_path for
// the hook, the basename variant when it does not (5.10), never taking the
// connect/sendmsg/exec hooks down with it.
func TestCreateLSMCollectionFileOpenVariant(t *testing.T) {
	object := func() map[string]int {
		return map[string]int{
			"wafio_bprm_check_security": 1,
			lsmProgFileOpen:             2,
			lsmProgFileOpenBasename:     3,
			"wafio_socket_connect":      4,
			lsmProgSendmsg:              5,
		}
	}
	// kernel rejects every listed program the way cilium/ebpf names it.
	load := func(programs map[string]int, rejected ...string) (func() ([]string, error), *int) {
		loads := 0
		return func() ([]string, error) {
			loads++
			var names []string
			for name := range programs {
				if slices.Contains(rejected, name) {
					return nil, fmt.Errorf("program %s: load program: invalid argument: helper call is not allowed in probe", name)
				}
				names = append(names, name)
			}
			slices.Sort(names)
			return names, nil
		}, &loads
	}
	run := func(programs map[string]int, rejected ...string) (loaded []string, dropped map[string]error, variant string, closed int, loads int, err error) {
		create, n := load(programs, rejected...)
		loaded, dropped, variant, err = createLSMCollection(programs, create, func([]string) { closed++ })
		return loaded, dropped, variant, closed, *n, err
	}

	t.Run("full variant accepted: basename never loaded", func(t *testing.T) {
		loaded, dropped, variant, closed, loads, err := run(object())
		if err != nil || variant != LSMFileOpenDPath || len(dropped) != 0 || closed != 0 || loads != 1 {
			t.Fatalf("variant=%q dropped=%v closed=%d loads=%d err=%v", variant, dropped, closed, loads, err)
		}
		if slices.Contains(loaded, lsmProgFileOpenBasename) || !slices.Contains(loaded, lsmProgFileOpen) {
			t.Fatalf("loaded = %v", loaded)
		}
	})
	t.Run("kernel 5.10: full rejected, basename takes over, other hooks kept", func(t *testing.T) {
		loaded, dropped, variant, closed, loads, err := run(object(), lsmProgFileOpen)
		if err != nil || variant != LSMFileOpenBasename {
			t.Fatalf("variant=%q err=%v", variant, err)
		}
		if closed != 1 || loads != 3 { // rejected, loaded without full (released), loaded with basename
			t.Fatalf("the first collection must be released: closed=%d loads=%d", closed, loads)
		}
		if _, ok := dropped[lsmProgFileOpen]; !ok || len(dropped) != 1 {
			t.Fatalf("dropped = %v", dropped)
		}
		want := []string{"wafio_bprm_check_security", lsmProgFileOpenBasename, "wafio_socket_connect", lsmProgSendmsg}
		if !slices.Equal(loaded, want) {
			t.Fatalf("loaded = %v, want %v", loaded, want)
		}
	})
	t.Run("full and sendmsg rejected: basename and connect stay", func(t *testing.T) {
		loaded, dropped, variant, _, _, err := run(object(), lsmProgFileOpen, lsmProgSendmsg)
		if err != nil || variant != LSMFileOpenBasename {
			t.Fatalf("variant=%q err=%v", variant, err)
		}
		if _, ok := dropped[lsmProgSendmsg]; !ok {
			t.Fatalf("dropped = %v", dropped)
		}
		if !slices.Contains(loaded, "wafio_socket_connect") || slices.Contains(loaded, lsmProgSendmsg) {
			t.Fatalf("loaded = %v", loaded)
		}
	})
	t.Run("both variants rejected: no file_open, rest loads", func(t *testing.T) {
		loaded, _, variant, _, _, err := run(object(), lsmProgFileOpen, lsmProgFileOpenBasename)
		if err != nil || variant != LSMFileOpenNone {
			t.Fatalf("variant=%q err=%v", variant, err)
		}
		want := []string{"wafio_bprm_check_security", "wafio_socket_connect", lsmProgSendmsg}
		if !slices.Equal(loaded, want) {
			t.Fatalf("loaded = %v, want %v", loaded, want)
		}
	})
	t.Run("a mandatory program rejected is an error", func(t *testing.T) {
		_, _, variant, _, _, err := run(object(), "wafio_socket_connect")
		if err == nil || variant != LSMFileOpenNone {
			t.Fatalf("variant=%q err=%v", variant, err)
		}
	})
	t.Run("older object without the basename variant", func(t *testing.T) {
		programs := object()
		delete(programs, lsmProgFileOpenBasename)
		_, _, variant, closed, loads, err := run(programs)
		if err != nil || variant != LSMFileOpenDPath || closed != 0 || loads != 1 {
			t.Fatalf("variant=%q closed=%d loads=%d err=%v", variant, closed, loads, err)
		}
		programs = object()
		delete(programs, lsmProgFileOpenBasename)
		_, _, variant, closed, loads, err = run(programs, lsmProgFileOpen)
		if err != nil || variant != LSMFileOpenNone || closed != 0 || loads != 2 {
			t.Fatalf("no fallback available: variant=%q closed=%d loads=%d err=%v", variant, closed, loads, err)
		}
	})
	t.Run("object with only the basename variant loads it", func(t *testing.T) {
		programs := object()
		delete(programs, lsmProgFileOpen)
		loaded, dropped, variant, closed, loads, err := run(programs)
		if err != nil || variant != LSMFileOpenBasename || len(dropped) != 0 || closed != 0 || loads != 1 {
			t.Fatalf("variant=%q dropped=%v closed=%d loads=%d err=%v", variant, dropped, closed, loads, err)
		}
		if !slices.Contains(loaded, lsmProgFileOpenBasename) {
			t.Fatalf("loaded = %v", loaded)
		}
	})
	t.Run("basename-only object rejected: dropped, rest loads", func(t *testing.T) {
		programs := object()
		delete(programs, lsmProgFileOpen)
		loaded, dropped, variant, _, _, err := run(programs, lsmProgFileOpenBasename)
		if err != nil || variant != LSMFileOpenNone || dropped[lsmProgFileOpenBasename] == nil {
			t.Fatalf("variant=%q dropped=%v err=%v", variant, dropped, err)
		}
		if slices.Contains(loaded, lsmProgFileOpenBasename) || !slices.Contains(loaded, "wafio_socket_connect") {
			t.Fatalf("loaded = %v", loaded)
		}
	})
	t.Run("reload after the d_path refusal fails once: hooks kept, no file_open", func(t *testing.T) {
		programs := object()
		loads := 0
		create := func() ([]string, error) {
			loads++
			if _, ok := programs[lsmProgFileOpen]; ok {
				return nil, fmt.Errorf("program %s: load program: invalid argument: helper call is not allowed in probe", lsmProgFileOpen)
			}
			if _, ok := programs[lsmProgFileOpenBasename]; ok {
				// the reload with the basename variant: transient failure on a mandatory program
				return nil, fmt.Errorf("program wafio_socket_connect: load program: cannot allocate memory")
			}
			var names []string
			for name := range programs {
				names = append(names, name)
			}
			slices.Sort(names)
			return names, nil
		}
		loaded, dropped, variant, err := createLSMCollection(programs, create, func([]string) {})
		if err != nil || variant != LSMFileOpenNone {
			t.Fatalf("variant=%q err=%v", variant, err)
		}
		if dropped[lsmProgFileOpenBasename] == nil || dropped[lsmProgFileOpen] == nil {
			t.Fatalf("dropped = %v", dropped)
		}
		if slices.Contains(loaded, lsmProgFileOpenBasename) || !slices.Contains(loaded, "wafio_bprm_check_security") || !slices.Contains(loaded, "wafio_socket_connect") {
			t.Fatalf("loaded = %v", loaded)
		}
	})
	t.Run("older object without file_open at all", func(t *testing.T) {
		programs := map[string]int{"wafio_bprm_check_security": 1}
		_, _, variant, _, _, err := run(programs)
		if err != nil || variant != LSMFileOpenNone {
			t.Fatalf("variant=%q err=%v", variant, err)
		}
	})
}

// Only the verifier's refusal of bpf_d_path selects the basename variant: a
// full variant rejected for any other reason stays dropped (variant none), and
// an error naming another program is never taken for it.
func TestCreateLSMCollectionFallbackOnlyForDPathRefusal(t *testing.T) {
	programs := func() map[string]int {
		return map[string]int{
			"wafio_bprm_check_security": 1,
			lsmProgFileOpen:             2,
			lsmProgFileOpenBasename:     3,
			"wafio_socket_connect":      4,
			lsmProgSendmsg:              5,
		}
	}
	// create fails with msg while the named program is still in the object.
	run := func(name, msg string) (dropped map[string]error, variant string, loads int) {
		p := programs()
		create := func() ([]string, error) {
			loads++
			if _, ok := p[name]; ok {
				return nil, fmt.Errorf("%s", msg)
			}
			return []string{"loaded"}, nil
		}
		_, dropped, variant, err := createLSMCollection(p, create, func([]string) {})
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		return dropped, variant, loads
	}

	t.Run("other verifier error: no fallback", func(t *testing.T) {
		dropped, variant, loads := run(lsmProgFileOpen, "program "+lsmProgFileOpen+": load program: permission denied: invalid indirect read")
		if variant != LSMFileOpenNone || loads != 2 || dropped[lsmProgFileOpen] == nil {
			t.Fatalf("variant=%q loads=%d dropped=%v", variant, loads, dropped)
		}
	})
	t.Run("error names another program: full variant dropped without fallback", func(t *testing.T) {
		// The generic path of createDroppingOptional drops every optional
		// program; a helper message that names wafio_socket_connect is not
		// the file_open refusal.
		dropped, variant, _ := run(lsmProgFileOpen, "program wafio_socket_connect: helper call is not allowed in probe")
		if variant != LSMFileOpenNone || dropped[lsmProgFileOpen] == nil {
			t.Fatalf("variant=%q dropped=%v", variant, dropped)
		}
	})
	t.Run("d_path refusal: fallback", func(t *testing.T) {
		dropped, variant, _ := run(lsmProgFileOpen, "program "+lsmProgFileOpen+": load program: invalid argument: helper call is not allowed in probe")
		if variant != LSMFileOpenBasename || dropped[lsmProgFileOpen] == nil {
			t.Fatalf("variant=%q dropped=%v", variant, dropped)
		}
	})
}

func TestReportedFileOpenVariant(t *testing.T) {
	for _, tc := range []struct {
		variant string
		hasHelp bool
		want    string
	}{
		{LSMFileOpenDPath, true, LSMFileOpenDPath},
		{LSMFileOpenDPath, false, LSMFileOpenBasename}, // 5.8/5.9: full program loaded, CO-RE guard takes the basename branch
		{LSMFileOpenBasename, true, LSMFileOpenBasename},
		{LSMFileOpenBasename, false, LSMFileOpenBasename},
		{LSMFileOpenNone, false, LSMFileOpenNone},
		{LSMFileOpenNone, true, LSMFileOpenNone},
	} {
		if got := reportedFileOpenVariant(tc.variant, tc.hasHelp); got != tc.want {
			t.Errorf("reportedFileOpenVariant(%q, %v) = %q, want %q", tc.variant, tc.hasHelp, got, tc.want)
		}
	}
}
