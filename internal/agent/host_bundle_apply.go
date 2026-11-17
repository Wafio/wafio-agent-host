package agent

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
	"log"
	"sync"
)

type hostBundleVersion struct {
	generation int64
	digest     [32]byte
}
type hostBundleApplier struct {
	mu       sync.Mutex
	versions map[string]hostBundleVersion
	apply    func([]byte, int64) error
}

// Versions survive reconnects within this process. They are not durable CAS.
var ebpfBundleApplier = hostBundleApplier{apply: applyEBPFBundle}

func (a *hostBundleApplier) applyBundle(bundle *agentv1.BundleUpdate) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	var sections map[string]json.RawMessage
	if err := json.Unmarshal(bundle.GetBundleJson(), &sections); err != nil {
		return err
	}
	generation := bundle.GetGeneration()
	if generation <= 0 {
		return fmt.Errorf("host bundle requires a positive generation")
	}
	duplicate := len(sections) > 0 && generation > 0
	for kind, raw := range sections {
		previous, ok := a.versions[kind]
		digest := sha256.Sum256(raw)
		if generation > 0 && ok {
			if generation < previous.generation {
				return fmt.Errorf("stale %s bundle generation", kind)
			}
			if generation == previous.generation && digest != previous.digest {
				// Same generation, different content: the control
				// plane changed what it delivers without a new revision
				// (a data migration, or a newer control plane that spells
				// out the state differently). Refusing kept the host on its
				// old state indefinitely; the stream is ordered and older
				// generations are still refused, so the latest delivery of
				// this generation is the control plane's current view.
				log.Printf("[host-bundle] %s generation %d re-delivered with different content; applying it", kind, generation)
			}
		}
		if !ok || previous.generation != generation || previous.digest != digest {
			duplicate = false
		}
	}
	if duplicate {
		return nil
	}
	if err := a.apply(bundle.GetBundleJson(), generation); err != nil {
		return err
	}
	if a.versions == nil {
		a.versions = make(map[string]hostBundleVersion)
	}
	if generation > 0 {
		for kind, raw := range sections {
			a.versions[kind] = hostBundleVersion{generation: generation, digest: sha256.Sum256(raw)}
		}
	}
	return nil
}
