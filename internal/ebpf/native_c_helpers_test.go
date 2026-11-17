package ebpf

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// bpfSourceHelper returns the body of a `static __always_inline` (or
// `static __noinline`) helper from a BPF C source under bpf/, so a test can
// compile the kernel logic natively with the BPF helpers and maps mocked.
// Verifier acceptance is a separate question, answered on the Linux lab,
// not here.
func bpfSourceHelper(t *testing.T, file, name string) string {
	t.Helper()
	source, err := os.ReadFile(filepath.Join("bpf", file))
	if err != nil {
		t.Fatal(err)
	}
	body := regexp.MustCompile(`(?s)static (?:__always_inline|__noinline) [\w *]+?\s*\n?\b` + name + `\(.*?\n\}`).FindString(string(source))
	if body == "" {
		t.Fatalf("%s: missing helper %s", file, name)
	}
	return body
}

// bpfSourceStruct returns the definition of `struct name { ... };` (attributes
// after the brace included) from a BPF C source or header under bpf/.
func bpfSourceStruct(t *testing.T, file, name string) string {
	t.Helper()
	source, err := os.ReadFile(filepath.Join("bpf", file))
	if err != nil {
		t.Fatal(err)
	}
	body := regexp.MustCompile(`(?s)\nstruct ` + name + ` \{.*?\n\}[^;\n]*;`).FindString(string(source))
	if body == "" {
		t.Fatalf("%s: missing struct %s", file, name)
	}
	return body + "\n"
}

// bpfSourceDefines returns the #define lines of a BPF C source whose macro
// name starts with one of the prefixes.
func bpfSourceDefines(t *testing.T, file string, prefixes ...string) string {
	t.Helper()
	source, err := os.ReadFile(filepath.Join("bpf", file))
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	for _, line := range strings.Split(string(source), "\n") {
		for _, p := range prefixes {
			if strings.HasPrefix(line, "#define "+p) {
				out.WriteString(line + "\n")
				break
			}
		}
	}
	return out.String()
}

// nativeCPrelude goes ahead of every native C harness, so no harness has to
// get the BPF annotations right on its own. glibc's <sys/cdefs.h> defines
// __always_inline, and a harness that redefined it after including libc
// headers failed with -Werror ("__always_inline" redefined) on Linux while
// passing on macOS (CI rounds 2 and 3). Here the libc headers come first and
// the annotations are then replaced; a harness that still defines them the
// same way (empty) is an identical, silent redefinition.
const nativeCPrelude = `#include <stdint.h>
#include <stdio.h>
#include <string.h>
#undef __always_inline
#define __always_inline
#undef __noinline
#define __noinline
#undef barrier_var
#define barrier_var(var) __asm__ __volatile__("" : "+r"(var))
`

// nativeCFlags: the one flag set for every harness. gcc rejects the BPF
// sources' `#pragma clang loop` under -Wall -Werror, hence
// -Wno-unknown-pragmas.
var nativeCFlags = []string{"-std=c11", "-Werror", "-Wall", "-Wno-unused-function", "-Wno-unknown-pragmas"}

// runNativeC compiles nativeCPrelude + src with the host C compiler
// (nativeCFlags) and runs it; a non-zero exit fails the test with the
// program's output. Skips without a compiler. Every native harness goes
// through here (TestNativeCHarnessesShareCompiler).
func runNativeC(t *testing.T, name, src string) string {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("native C compiler unavailable")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, name+".c")
	if err := os.WriteFile(path, []byte(nativeCPrelude+src), 0600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, name)
	args := append(append([]string{}, nativeCFlags...), path, "-o", bin)
	if out, err := exec.Command(cc, args...).CombinedOutput(); err != nil {
		if strings.Contains(string(out), "Xcode license") {
			t.Skipf("skipping because Xcode license agreement is pending: %s", out)
		}
		t.Fatalf("compile %s: %s: %v", name, out, err)
	}
	out, err := exec.Command(bin).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %s: %v", name, out, err)
	}
	return string(out)
}

// TestNativeCHarnessesShareCompiler keeps every native C harness on
// runNativeC: a harness with its own compiler call would miss the prelude
// and the flags, which is how four harnesses broke Linux CI at once.
func TestNativeCHarnessesShareCompiler(t *testing.T) {
	files, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if f == "native_c_helpers_test.go" {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(src), `exec.LookPath("cc")`) {
			t.Errorf("%s looks up the C compiler itself; compile through runNativeC", f)
		}
	}
}
