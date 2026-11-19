//go:build linux

package ebpf

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// fakeKernelMap stands in for a BPF map and records every write in a log it
// shares with the other fakes, so a test can check the order of writes across
// maps.
type fakeKernelMap struct {
	name       string
	valueSize  uint32
	maxEntries uint32 // the budget map of the current object: 3 slots
	ops        *[]string
	data       map[any]any
	iterations int // how many times the map was iterated
}

func newFakeKernelMap(name string, valueSize uint32, ops *[]string) *fakeKernelMap {
	return &fakeKernelMap{name: name, valueSize: valueSize, maxEntries: 3, ops: ops, data: make(map[any]any)}
}

func (m *fakeKernelMap) ValueSize() uint32 { return m.valueSize }

func (m *fakeKernelMap) MaxEntries() uint32 { return m.maxEntries }

func (m *fakeKernelMap) Update(key, value any, _ ebpf.MapUpdateFlags) error {
	*m.ops = append(*m.ops, fmt.Sprintf("%s update %v", m.name, key))
	m.data[key] = value
	return nil
}

func (m *fakeKernelMap) Delete(key any) error {
	*m.ops = append(*m.ops, fmt.Sprintf("%s delete %v", m.name, key))
	if _, ok := m.data[key]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(m.data, key)
	return nil
}

func (m *fakeKernelMap) Lookup(key, valueOut any) error {
	v, ok := m.data[key]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	reflect.ValueOf(valueOut).Elem().Set(reflect.ValueOf(v))
	return nil
}

type fakeIterator struct {
	keys, values []any
	next         int
}

func (m *fakeKernelMap) Iterate() mapIterator {
	m.iterations++
	it := &fakeIterator{}
	for k, v := range m.data {
		it.keys, it.values = append(it.keys, k), append(it.values, v)
	}
	return it
}

func (it *fakeIterator) Next(keyOut, valueOut any) bool {
	if it.next >= len(it.keys) {
		return false
	}
	reflect.ValueOf(keyOut).Elem().Set(reflect.ValueOf(it.keys[it.next]))
	reflect.ValueOf(valueOut).Elem().Set(reflect.ValueOf(it.values[it.next]))
	it.next++
	return true
}

func (it *fakeIterator) Err() error { return nil }

// The refresh writes the image map before it writes any tgid entry: an entry
// written first could meet an exec whose image the kernel does not know yet and
// be dropped, or, worse, an image written after it leaves a window in which the
// previous set is the one the kernel trusts.
func TestSyncProtectedTGIDsWritesImagesFirst(t *testing.T) {
	asTrustedOwner(t)
	dir := imageTestDir(t)
	agent := writeFile(t, filepath.Join(dir, "agentd"), "agent", 0o755)
	set := NewProtectedProcessSetFromConfig(ProtectedProcessConfig{ExePaths: []string{agent}, ReplaceDefaults: true})
	proc := fakeProc(t, map[uint32]fakeProcEntry{
		700: {exe: agent, comm: "agentd", uid: "999", mntns: hostNS, hostExe: true, start: 1234},
	})
	if err := os.Symlink("/proc/self", filepath.Join(proc, "1")); err != nil {
		t.Fatal(err)
	}

	var ops []string
	tm := &TraceManager{
		log:                log.New(io.Discard, "", 0),
		protected:          set,
		procRoot:           proc,
		execKeep:           true,
		protectedMap:       newFakeKernelMap("tgids", 8, &ops),
		protectedImagesMap: newFakeKernelMap("images", uint32(len(protectedImage{}.Unit))+8, &ops),
		protectedBudgetMap: newFakeKernelMap("budget", 8, &ops),
	}
	matched, err := tm.syncProtectedTGIDs()
	if err != nil || matched != 1 {
		t.Fatalf("sync: matched %d, error %v", matched, err)
	}
	firstImage := slices.IndexFunc(ops, func(op string) bool { return strings.HasPrefix(op, "images update") })
	firstTGID := slices.IndexFunc(ops, func(op string) bool { return op == "tgids update 700" })
	if firstImage < 0 || firstTGID < 0 || firstImage > firstTGID {
		t.Fatalf("the image map is written at %d and the first tgid entry at %d; operations:\n%s", firstImage, firstTGID, strings.Join(ops, "\n"))
	}
	// The budget follows the map: one entry written, so 767 inserts of 768, with
	// the limit written first so the kernel never gives back above the budget.
	limit := slices.Index(ops, fmt.Sprintf("budget update %d", protectedLimitSlot))
	budget := slices.Index(ops, fmt.Sprintf("budget update %d", protectedBudgetSlot))
	if limit < 0 || budget < 0 || limit > budget {
		t.Fatalf("limit written at %d and budget at %d, want the limit first; operations:\n%s", limit, budget, strings.Join(ops, "\n"))
	}
	for _, slot := range []uint32{protectedLimitSlot, protectedBudgetSlot} {
		if got := tm.protectedBudgetMap.(*fakeKernelMap).data[slot]; got != int64(maxInheritedFill-1) {
			t.Errorf("budget slot %d holds %v, want %d", slot, got, maxInheritedFill-1)
		}
	}
}

// Fork inheritance is turned off before the fork probe attaches when the exec
// probe is not linked, and the kernel is told: budget and limit both 0, so the
// units it gives back at exit cannot raise it.
func TestDisableInheritWithoutExec(t *testing.T) {
	var ops []string
	budget := newFakeKernelMap("budget", 8, &ops)
	tm := &TraceManager{log: log.New(io.Discard, "", 0), execKeep: true, protectedBudgetMap: budget, protectedTGIDs: map[uint32]uint64{1: 1, 2: 2}}

	tm.disableInheritWithoutExec("sched_process_exec")
	tm.linkNames = []string{"sched_process_exec"}
	tm.disableInheritWithoutExec("sched_process_fork")
	if !tm.execKeep || len(ops) != 0 {
		t.Fatalf("inheritance turned off with the exec probe linked or for another probe: keep %t, operations %v", tm.execKeep, ops)
	}

	tm.linkNames = []string{"sched_process_exit"}
	tm.disableInheritWithoutExec("sched_process_exit")
	if !tm.execKeep {
		t.Fatal("inheritance turned off before the fork probe")
	}
	tm.disableInheritWithoutExec("sched_process_fork")
	if tm.execKeep {
		t.Fatal("the fork probe attaches without the exec probe and inheritance is still on")
	}
	for _, slot := range []uint32{protectedLimitSlot, protectedBudgetSlot} {
		if got := budget.data[slot]; got != int64(0) {
			t.Errorf("budget slot %d holds %v after inheritance went off, want 0", slot, got)
		}
	}
	if ops[0] != fmt.Sprintf("budget update %d", protectedLimitSlot) {
		t.Errorf("the limit is not written first: %v", ops)
	}
	// An object without the budget map has nothing to tell.
	bare := &TraceManager{log: log.New(io.Discard, "", 0), execKeep: true}
	bare.disableInheritWithoutExec("sched_process_fork")
	if bare.execKeep {
		t.Error("inheritance stays on without the exec probe when the object has no budget map")
	}
}

// The budget the refresh writes leaves room below the map's capacity for the
// entries it writes itself, and is 0 whenever the exec keep is off.
func TestUpdateProtectedBudgetValues(t *testing.T) {
	for _, tc := range []struct {
		entries int
		keep    bool
		want    int64
	}{{0, true, 768}, {10, true, 758}, {768, true, 0}, {10, false, 0}} {
		var ops []string
		budget := newFakeKernelMap("budget", 8, &ops)
		tm := &TraceManager{log: log.New(io.Discard, "", 0), execKeep: tc.keep, protectedBudgetMap: budget}
		tm.updateProtectedBudget(tc.entries)
		for _, slot := range []uint32{protectedLimitSlot, protectedBudgetSlot} {
			if got := budget.data[slot]; got != tc.want {
				t.Errorf("%d entries, keep %t: slot %d holds %v, want %d", tc.entries, tc.keep, slot, got, tc.want)
			}
		}
	}
	// A failing write is logged and does not stop the other slot.
	failing := &failingMap{fakeKernelMap: newFakeKernelMap("budget", 8, new([]string))}
	tm := &TraceManager{log: log.New(io.Discard, "", 0), execKeep: true, protectedBudgetMap: failing}
	tm.updateProtectedBudget(0)
	if _, ok := failing.data[protectedBudgetSlot]; !ok {
		t.Error("the budget was not written after the limit failed")
	}
}

// An object with a two-slot budget map has no limit slot: the refresh leaves it
// out, so the kernel's refusal of the write never reaches the log.
func TestUpdateProtectedBudgetOnTwoSlotMap(t *testing.T) {
	var out bytes.Buffer
	budget := newFakeKernelMap("budget", 8, new([]string))
	budget.maxEntries = 2
	tm := &TraceManager{log: log.New(&out, "", 0), protectedBudgetMap: arrayMap{budget}}
	for range 3 {
		tm.updateProtectedBudget(5)
	}
	if out.Len() != 0 {
		t.Fatalf("the refresh logged:\n%s", out.String())
	}
	if got := budget.data[protectedBudgetSlot]; got != int64(0) {
		t.Fatalf("budget slot holds %v, want 0", got)
	}
}

// arrayMap refuses a key past the capacity, as the kernel does for an array.
type arrayMap struct{ *fakeKernelMap }

func (m arrayMap) Update(key, value any, flags ebpf.MapUpdateFlags) error {
	if k, ok := key.(uint32); ok && k >= m.maxEntries {
		return unix.E2BIG
	}
	return m.fakeKernelMap.Update(key, value, flags)
}

type failingMap struct{ *fakeKernelMap }

func (m *failingMap) Update(key, value any, flags ebpf.MapUpdateFlags) error {
	if key == protectedLimitSlot {
		return errors.New("full")
	}
	return m.fakeKernelMap.Update(key, value, flags)
}

// The periodic refresh watches again the directories of trusted files that did
// not exist, or were moved, and the change of a file in one of them refreshes
// the images at once.
func TestRefreshOnTickRearmsTheWatch(t *testing.T) {
	asTrustedOwner(t)
	base := imageTestDir(t)
	dir := filepath.Join(base, "later")
	agent := filepath.Join(dir, "agentd")
	set := NewProtectedProcessSetFromConfig(ProtectedProcessConfig{ExePaths: []string{agent}, ReplaceDefaults: true})
	proc := selfProc(t)
	w, err := watchProtectedImages(set, proc)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	var ops []string
	images := newFakeKernelMap("images", 56, &ops)
	tm := &TraceManager{
		log:                log.New(io.Discard, "", 0),
		protected:          set,
		procRoot:           proc,
		execKeep:           true,
		protectedMap:       newFakeKernelMap("tgids", 8, &ops),
		protectedImagesMap: images,
		protectedBudgetMap: newFakeKernelMap("budget", 8, &ops),
	}
	tm.refreshOnTick(w)
	if w.armedDirs() != 0 || len(images.data) != 0 {
		t.Fatalf("a directory that does not exist is watched (%d) or has an image (%d)", w.armedDirs(), len(images.data))
	}
	writeFile(t, agent, "agent", 0o755) // creates the directory too
	tm.refreshOnTick(w)
	if w.armedDirs() != 1 {
		t.Fatalf("%d directories watched after the refresh, want 1", w.armedDirs())
	}
	if len(images.data) != 1 {
		t.Fatalf("the image of the new file was not written: %d images", len(images.data))
	}
	// The directory is watched now: the replacement of the file refreshes the
	// image set between two ticks.
	select {
	case <-w.changed:
	default:
	}
	if err := os.Rename(writeFile(t, agent+".new", "new agent", 0o755), agent); err != nil {
		t.Fatal(err)
	}
	select {
	case <-w.changed:
	case <-time.After(5 * time.Second):
		t.Fatal("the replacement of a trusted file did not signal")
	}
	tm.refreshOnChange(w)
	if len(images.data) != 1 {
		t.Fatalf("after the replacement the map holds %d images, want the new one alone", len(images.data))
	}
}

// A burst of renames of a trusted file refreshes the images a few times, not
// once per rename, and the image of the last file is in the map when it ends.
func TestProtectedRefreshLoopLimitsChangeRefreshes(t *testing.T) {
	asTrustedOwner(t)
	dir := imageTestDir(t)
	agent := writeFile(t, filepath.Join(dir, "agentd"), "agent", 0o755)
	const renames = 20
	for i := range renames {
		writeFile(t, fmt.Sprintf("%s.%d", agent, i), fmt.Sprintf("agent %d", i), 0o755)
	}
	set := NewProtectedProcessSetFromConfig(ProtectedProcessConfig{ExePaths: []string{agent}, ReplaceDefaults: true})
	proc := selfProc(t)
	var ops []string
	images := newFakeKernelMap("images", uint32(len(protectedImage{}.Unit))+8, &ops)
	tm := &TraceManager{
		log:                log.New(io.Discard, "", 0),
		protected:          set,
		procRoot:           proc,
		execKeep:           true,
		protectedMap:       newFakeKernelMap("tgids", 8, &ops),
		protectedImagesMap: images,
		protectedBudgetMap: newFakeKernelMap("budget", 8, &ops),
	}
	done := make(chan struct{})
	tm.wg.Add(1)
	go tm.protectedRefreshLoop(done)
	time.Sleep(100 * time.Millisecond) // the loop arms its watch first
	for i := range renames {
		if err := os.Rename(fmt.Sprintf("%s.%d", agent, i), agent); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(1500 * time.Millisecond)
	close(done)
	tm.wg.Wait()

	if images.iterations > 3 {
		t.Errorf("%d refreshes for %d renames in 200 ms, want at most 3", images.iterations, renames)
	}
	want := set.kernelImages(proc, nil)
	if len(want) != 1 {
		t.Fatalf("the last file has %d images, want 1", len(want))
	}
	for key := range want {
		if _, ok := images.data[key]; !ok {
			t.Errorf("the image of the last file is not in the map after %d refreshes: %v", images.iterations, images.data)
		}
	}
}

// A protected process whose file an account other than root can write is not
// protected: the refresh says so once for each path, forgets a path that was
// fixed and says so again when it comes back.
func TestSyncProtectedTGIDsReportsUntrustedOwnerOnce(t *testing.T) {
	const path = "/usr/local/bin/kubelet"
	proc := fakeProc(t, map[uint32]fakeProcEntry{
		700: {exe: path, comm: "kubelet", uid: "0", mntns: hostNS, start: 1234, untrusted: path},
	})
	var out bytes.Buffer
	var ops []string
	tm := &TraceManager{log: log.New(&out, "", 0), protected: NewProtectedProcessSet(nil, nil), procRoot: proc, protectedMap: newFakeKernelMap("tgids", 8, &ops)}
	reports := func() int {
		t.Helper()
		if _, err := tm.syncProtectedTGIDs(); err != nil {
			t.Fatal(err)
		}
		return strings.Count(out.String(), path+" can be written by an account other than root")
	}
	if n := reports(); n != 1 {
		t.Fatalf("the first scan reported the path %d times, want 1:\n%s", n, out.String())
	}
	if n := reports(); n != 1 {
		t.Fatalf("the next scan reported it again (%d lines in all)", n)
	}
	if got := sortedKeys(tm.protectedUntrusted); !slices.Equal(got, []string{path}) {
		t.Fatalf("untrusted set %v, want [%s]", got, path)
	}
	dir := filepath.Join(proc, "700")
	if err := os.Remove(filepath.Join(dir, "fake_untrusted")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fake_host_exe"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if n := reports(); n != 1 || len(tm.protectedUntrusted) != 0 {
		t.Fatalf("after the fix: %d lines, untrusted %v, want the set empty", n, sortedKeys(tm.protectedUntrusted))
	}
	if err := os.Remove(filepath.Join(dir, "fake_host_exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fake_untrusted"), []byte(path), 0o644); err != nil {
		t.Fatal(err)
	}
	if n := reports(); n != 2 {
		t.Fatalf("a path that came back was reported %d times in all, want 2", n)
	}
}
