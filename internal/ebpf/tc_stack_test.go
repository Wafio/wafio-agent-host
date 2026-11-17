package ebpf

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// tcStackBudget is the most stack a TC program plus its deepest call chain may
// use, rounded per frame to 32 bytes the way the verifier does. The hard
// limit is MAX_BPF_STACK (512); the 32 bytes below it are headroom so one more
// local in wafio_tc_egress does not make the verifier reject the program on
// every kernel (the frame sat at exactly 512 with parse_packet).
const tcStackBudget = 480

func roundStack32(n int) int { return (n + 31) / 32 * 32 }

// bpfToolchain returns clang and llvm-objdump, or skips the test.
func bpfToolchain(t *testing.T) (clang, objdump string) {
	t.Helper()
	clang, err := exec.LookPath("clang")
	if err != nil {
		t.Skip("clang not installed")
	}
	objdump, err = exec.LookPath("llvm-objdump")
	if err != nil {
		t.Skip("llvm-objdump not installed")
	}
	return clang, objdump
}

// bpfObjectStack compiles src and returns the per-function stack analysis of
// the object.
func bpfObjectStack(t *testing.T, clang, objdump, src string, cflags ...string) *bpfStackInfo {
	t.Helper()
	// Read the sources through the test process: clang opens them in a
	// subprocess, which go test's result cache does not see, so an edited
	// .c/.h file would otherwise replay a cached (stale) stack report.
	for _, pattern := range []string{src, filepath.Join(filepath.Dir(src), "*.h")} {
		files, _ := filepath.Glob(pattern)
		for _, f := range files {
			if _, err := os.ReadFile(f); err != nil {
				t.Fatalf("read %s: %v", f, err)
			}
		}
	}
	obj := filepath.Join(t.TempDir(), "prog.o")
	args := append([]string{"-O2", "-g", "-target", "bpf"}, cflags...)
	args = append(args, "-c", src, "-o", obj)
	if out, err := exec.Command(clang, args...).CombinedOutput(); err != nil {
		if strings.Contains(string(out), "bpf_helpers.h' file not found") {
			t.Skip("libbpf headers not installed (set WAFIO_BPF_INCLUDE)")
		}
		t.Fatalf("clang: %v\n%s", err, out)
	}
	syms, err := exec.Command(objdump, "-t", obj).Output()
	if err != nil {
		t.Fatalf("llvm-objdump -t: %v", err)
	}
	dump, err := exec.Command(objdump, "-dr", obj).Output()
	if err != nil {
		t.Fatalf("llvm-objdump -dr: %v", err)
	}
	info, err := parseBPFStack(string(syms), string(dump))
	if err != nil {
		t.Fatalf("parse object: %v", err)
	}
	return info
}

// TestTCStackHeadroom compiles wafio_tc.c and checks, for each program
// (wafio_tc_egress / wafio_tc_ingress), the verifier's stack rule: the sum of
// the 32-byte-rounded frames along its deepest call chain. Skipped when clang,
// llvm-objdump or the libbpf headers are missing (WAFIO_BPF_INCLUDE = a
// directory holding bpf/bpf_helpers.h).
func TestTCStackHeadroom(t *testing.T) {
	clang, objdump := bpfToolchain(t)
	for _, cpu := range []string{"-mcpu=v1", "-mcpu=v2"} {
		t.Run(cpu, func(t *testing.T) {
			flags := []string{cpu, "-D__TARGET_ARCH_x86_64", "-Ibpf", "-I/usr/include"}
			if inc := os.Getenv("WAFIO_BPF_INCLUDE"); inc != "" {
				flags = append(flags, "-I"+inc)
			}
			info := bpfObjectStack(t, clang, objdump, filepath.Join("bpf", "wafio_tc.c"), flags...)
			for _, p := range []string{"wafio_tc_egress", "wafio_tc_ingress"} {
				total, chain, err := info.chainDepth(p)
				if err != nil {
					t.Fatalf("%s: %v", p, err)
				}
				t.Logf("%s: %s = %d of %d", p, chain, total, tcStackBudget)
				if total > tcStackBudget {
					t.Errorf("%s uses %d B of BPF stack along %s; keep it <= %d (limit 512): move locals to a per-CPU map", p, total, chain, tcStackBudget)
				}
			}
		})
	}
}

// TestTCStackHeadroomCatchesOverflow compiles a program whose call chain
// needs more than 512 B and checks the analysis sees it (and ignores a large
// function nothing calls).
func TestTCStackHeadroomCatchesOverflow(t *testing.T) {
	clang, objdump := bpfToolchain(t)
	src := filepath.Join(t.TempDir(), "deep.c")
	const code = `
#define SEC(n) __attribute__((section(n), used))
#define NOINLINE __attribute__((noinline))
static NOINLINE int leaf(volatile unsigned char *p, int n) {
	volatile unsigned char buf[200];
	for (int i = 0; i < 200; i++) buf[i] = p[i & 7] + n;
	return buf[n & 127];
}
static NOINLINE int mid(int n) {
	volatile unsigned char buf[200];
	for (int i = 0; i < 200; i++) buf[i] = n + i;
	return leaf(buf, n) + buf[n & 63];
}
NOINLINE int unused_big(int n) {
	volatile unsigned char buf[480];
	for (int i = 0; i < 480; i++) buf[i] = n;
	return buf[n & 255];
}
SEC("tc") int deep_prog(void *ctx) {
	volatile unsigned char buf[160];
	for (int i = 0; i < 160; i++) buf[i] = (unsigned long)ctx + i;
	return mid(buf[3]) + buf[7];
}
SEC("tc") int shallow_prog(void *ctx) {
	volatile unsigned char buf[64];
	for (int i = 0; i < 64; i++) buf[i] = (unsigned long)ctx + i;
	return buf[5];
}
char LICENSE[] SEC("license") = "GPL";
`
	if err := os.WriteFile(src, []byte(code), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, cpu := range []string{"-mcpu=v1", "-mcpu=v2"} {
		t.Run(cpu, func(t *testing.T) {
			info := bpfObjectStack(t, clang, objdump, src, cpu)
			total, chain, err := info.chainDepth("deep_prog")
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("deep_prog: %s = %d", chain, total)
			if total <= 512 || !strings.Contains(chain, "leaf") {
				t.Errorf("deep_prog chain %s = %d B, want > 512 through leaf", chain, total)
			}
			total, chain, err = info.chainDepth("shallow_prog")
			if err != nil {
				t.Fatal(err)
			}
			if total > 128 {
				t.Errorf("shallow_prog %s = %d B: a function it does not call was counted", chain, total)
			}
		})
	}
}

// bpfFunc is one function symbol of a BPF object.
type bpfFunc struct {
	name    string
	section string
	start   int // byte offset in its section
	size    int
	frame   int      // largest r10 offset it touches
	callees []string // BPF-to-BPF calls (pseudo calls)
}

type bpfStackInfo struct {
	funcs map[string]*bpfFunc
}

var (
	objdumpSym     = regexp.MustCompile(`^([0-9a-f]+) (.{7}) (\S+)\s+([0-9a-f]+) (\S+)$`)
	objdumpSection = regexp.MustCompile(`^Disassembly of section (\S+):$`)
	objdumpInsn    = regexp.MustCompile(`^\s*(\d+):\t([0-9a-f ]+)\t(.*)$`)
	objdumpReloc   = regexp.MustCompile(`^\s+[0-9a-f]+:\s+R_BPF_64_32\s+(\S+)`)
	objdumpStack   = regexp.MustCompile(`r10 - (0x[0-9a-f]+|\d+)`)
	objdumpCopy    = regexp.MustCompile(`^(r\d+) = r10$`)
	objdumpAdd     = regexp.MustCompile(`^(r\d+) \+= -(0x[0-9a-f]+|\d+)$`)
)

// parseBPFStack reads `llvm-objdump -t` (symbols) and `llvm-objdump -dr`
// (disassembly with raw bytes and relocations) of a BPF object. Functions are
// the symbol table's F symbols, by address range: labels objdump prints inside
// a function (clang 18 keeps LBB* local symbols in the object) do not start a
// new one. Calls are BPF pseudo calls (opcode 0x85, src_reg 1), resolved the
// way libbpf does: target = base + (imm+1)*8, base = the relocation symbol's
// value (a section symbol = 0) or, without a relocation, the call itself.
func parseBPFStack(syms, dump string) (*bpfStackInfo, error) {
	info := &bpfStackInfo{funcs: map[string]*bpfFunc{}}
	symSection := map[string]string{}
	for _, line := range strings.Split(syms, "\n") {
		m := objdumpSym.FindStringSubmatch(strings.TrimRight(line, " "))
		if m == nil {
			continue
		}
		start, _ := strconv.ParseInt(m[1], 16, 64)
		size, _ := strconv.ParseInt(m[4], 16, 64)
		symSection[m[5]] = m[3]
		if strings.Contains(m[2], "F") {
			info.funcs[m[5]] = &bpfFunc{name: m[5], section: m[3], start: int(start), size: int(size)}
		}
	}
	at := func(sec string, off int) *bpfFunc {
		for _, f := range info.funcs {
			if f.section == sec && off >= f.start && off < f.start+f.size {
				return f
			}
		}
		return nil
	}

	type call struct {
		from     *bpfFunc
		sec      string
		off, imm int
		relocSym string
		hasReloc bool
	}
	var calls []*call
	var last *call
	sec := ""
	copies := map[*bpfFunc]map[string]bool{}
	for _, line := range strings.Split(dump, "\n") {
		if m := objdumpSection.FindStringSubmatch(line); m != nil {
			sec, last = m[1], nil
			continue
		}
		if m := objdumpReloc.FindStringSubmatch(line); m != nil {
			if last != nil {
				last.relocSym, last.hasReloc = m[1], true
			}
			continue
		}
		m := objdumpInsn.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		last = nil
		idx, _ := strconv.Atoi(m[1])
		off := idx * 8
		fn := at(sec, off)
		if fn == nil {
			continue
		}
		raw, err := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(m[2]), " ", ""))
		if err != nil || len(raw) < 8 {
			return nil, fmt.Errorf("instruction bytes %q", m[2])
		}
		if raw[0] == 0x85 && raw[1]>>4 == 1 { // BPF_JMP|BPF_CALL, src_reg BPF_PSEUDO_CALL
			last = &call{from: fn, sec: sec, off: off, imm: int(int32(binary.LittleEndian.Uint32(raw[4:8])))}
			calls = append(calls, last)
		}
		insn := m[3]
		if copies[fn] == nil {
			copies[fn] = map[string]bool{}
		}
		if c := objdumpCopy.FindStringSubmatch(insn); c != nil {
			copies[fn][c[1]] = true
		} else if c := objdumpAdd.FindStringSubmatch(insn); c != nil && copies[fn][c[1]] {
			if v, err := strconv.ParseInt(c[2], 0, 32); err == nil && int(v) > fn.frame {
				fn.frame = int(v)
			}
		}
		for _, s := range objdumpStack.FindAllStringSubmatch(insn, -1) {
			if v, err := strconv.ParseInt(s[1], 0, 32); err == nil && int(v) > fn.frame {
				fn.frame = int(v)
			}
		}
	}

	for _, c := range calls {
		sec, base := c.sec, c.off
		if c.hasReloc {
			if f, ok := info.funcs[c.relocSym]; ok {
				sec, base = f.section, f.start
			} else {
				sec, base = c.relocSym, 0 // section symbol
				if s, ok := symSection[c.relocSym]; ok {
					sec = s
				}
			}
		}
		target := base + (c.imm+1)*8
		callee := at(sec, target)
		if callee == nil || callee.start != target {
			return nil, fmt.Errorf("%s: call at %s+%#x does not reach a function start (%s+%#x)", c.from.name, c.sec, c.off, sec, target)
		}
		c.from.callees = append(c.from.callees, callee.name)
	}
	return info, nil
}

// chainDepth returns the verifier's stack depth for program name: the
// largest sum of 32-byte-rounded frames over the call chains starting at it,
// and that chain.
func (s *bpfStackInfo) chainDepth(name string) (int, string, error) {
	var walk func(n string, seen map[string]bool) (int, []string, error)
	walk = func(n string, seen map[string]bool) (int, []string, error) {
		f, ok := s.funcs[n]
		if !ok {
			return 0, nil, fmt.Errorf("function %s not found in the object", n)
		}
		if seen[n] {
			return 0, nil, fmt.Errorf("recursive call to %s", n)
		}
		seen[n] = true
		defer delete(seen, n)
		best, bestChain := 0, []string(nil)
		callees := append([]string(nil), f.callees...)
		sort.Strings(callees)
		for _, c := range callees {
			d, chain, err := walk(c, seen)
			if err != nil {
				return 0, nil, err
			}
			if d > best {
				best, bestChain = d, chain
			}
		}
		own := fmt.Sprintf("%s %d (rounded %d)", n, f.frame, roundStack32(f.frame))
		return roundStack32(f.frame) + best, append([]string{own}, bestChain...), nil
	}
	d, chain, err := walk(name, map[string]bool{})
	return d, strings.Join(chain, " + "), err
}

func TestBPFStackParser(t *testing.T) {
	syms := "SYMBOL TABLE:\n" +
		"0000000000000000 l    d  .text\t0000000000000000 .text\n" +
		"0000000000000000 l     F .text\t0000000000000018 helper_a\n" +
		"0000000000000018 l     F .text\t0000000000000010 unused\n" +
		"0000000000000010 l       tc\t0000000000000000 LBB0_2\n" +
		"0000000000000000 g     F tc\t0000000000000030 prog\n" +
		"0000000000000030 g     F tc\t0000000000000008 prog2\n"
	dump := "Disassembly of section .text:\n\n" +
		"0000000000000000 <helper_a>:\n" +
		"       0:\t7b 1a e0 ff 00 00 00 00\t*(u64 *)(r10 - 0x20) = r1\n" +
		"       1:\tbf a2 00 00 00 00 00 00\tr2 = r10\n" +
		"       2:\t07 02 00 00 c0 ff ff ff\tr2 += -0x40\n" +
		"0000000000000018 <unused>:\n" +
		"       3:\t63 3a 48 fe 00 00 00 00\t*(u32 *)(r10 - 440) = r3\n" +
		"       4:\t95 00 00 00 00 00 00 00\texit\n\n" +
		"Disassembly of section tc:\n\n" +
		"0000000000000000 <prog>:\n" +
		"       0:\t7b 1a 80 fe 00 00 00 00\t*(u64 *)(r10 - 0x180) = r1\n" +
		"       1:\t85 10 00 00 ff ff ff ff\tcall -0x1\n" +
		"\t\t0000000000000008:  R_BPF_64_32\t.text\n" +
		"0000000000000010 <LBB0_2>:\n" +
		"       2:\t7b 1a 70 fe 00 00 00 00\t*(u64 *)(r10 - 0x190) = r1\n" +
		"       3:\t85 00 00 00 01 00 00 00\tcall 0x1\n" +
		"       4:\t85 10 00 00 01 00 00 00\tcall 0x1\n" +
		"       5:\t95 00 00 00 00 00 00 00\texit\n" +
		"0000000000000030 <prog2>:\n" +
		"       6:\t95 00 00 00 00 00 00 00\texit\n"
	info, err := parseBPFStack(syms, dump)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := info.funcs["LBB0_2"]; ok {
		t.Fatal("label parsed as a function")
	}
	if got := info.funcs["prog"].frame; got != 0x190 {
		t.Fatalf("prog frame %d, want 400 (label must not end the function)", got)
	}
	if got := info.funcs["helper_a"].frame; got != 64 {
		t.Fatalf("helper_a frame %d, want 64", got)
	}
	// The helper call (src_reg 0) is ignored; a pseudo call without a
	// relocation is relative to itself (insn 4 + 1 + 1 = prog2).
	if got := info.funcs["prog"].callees; len(got) != 2 || got[0] != "helper_a" || got[1] != "prog2" {
		t.Fatalf("callees %v", got)
	}
	// unused (440 B) is not on prog's chains: 416 + 64.
	if d, chain, err := info.chainDepth("prog"); err != nil || d != 480 {
		t.Fatalf("chainDepth(prog) = %d %q %v, want 480", d, chain, err)
	}
	bad := strings.Replace(dump, "85 10 00 00 01 00 00 00\tcall 0x1", "85 10 00 00 00 00 00 00\tcall 0x0", 1)
	if _, err := parseBPFStack(syms, bad); err == nil {
		t.Fatal("call into the middle of a function accepted")
	}
	if roundStack32(440) != 448 || roundStack32(392) != 416 {
		t.Fatal("rounding")
	}
}
