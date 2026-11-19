//go:build linux

package ebpf

import "github.com/cilium/ebpf"

// mapIterator is the part of *ebpf.MapIterator the protected-set sync uses.
type mapIterator interface {
	Next(keyOut, valueOut any) bool
	Err() error
}

// kernelMap is the part of *ebpf.Map the protected-set sync uses, so a test can
// stand in for the kernel and look at what is written, and in which order.
type kernelMap interface {
	ValueSize() uint32
	MaxEntries() uint32
	Update(key, value any, flags ebpf.MapUpdateFlags) error
	Delete(key any) error
	Lookup(key, valueOut any) error
	Iterate() mapIterator
}

type realKernelMap struct{ *ebpf.Map }

func (m realKernelMap) Iterate() mapIterator { return m.Map.Iterate() }

// kernelMapOf wraps a map of the loaded object, or returns nil (an interface
// holding a nil pointer would not compare equal to nil) for an object without
// it.
func kernelMapOf(m *ebpf.Map) kernelMap {
	if m == nil {
		return nil
	}
	return realKernelMap{m}
}
