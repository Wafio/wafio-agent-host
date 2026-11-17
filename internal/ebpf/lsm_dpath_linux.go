//go:build linux

package ebpf

import "github.com/cilium/ebpf/btf"

// kernelHasDPath reports whether the running kernel's BTF enum bpf_func_id
// lists BPF_FUNC_d_path, the same test the CO-RE guard in wafio_lsm.c makes
// (bpf_core_enum_value_exists). Any BTF error reads as "no": the object could
// not have been relocated without BTF anyway.
func kernelHasDPath() bool {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return false
	}
	var funcs *btf.Enum
	if err := spec.TypeByName("bpf_func_id", &funcs); err != nil {
		return false
	}
	for _, v := range funcs.Values {
		if v.Name == "BPF_FUNC_d_path" {
			return true
		}
	}
	return false
}
