package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ContainerInfo holds metadata about a running container, used to enrich
// eBPF trace events with human-readable container context.
type ContainerInfo struct {
	ContainerID    string            // short container ID (12 chars)
	ContainerImage string            // image:tag
	ContainerName  string            // container name (without leading /)
	IsPrivileged   bool              // container runs --privileged
	K8sPod         string            // kubernetes.io/pod-name label, if present
	K8sNamespace   string            // kubernetes.io/namespace label, if present
	Labels         map[string]string // all container labels
	CgroupIDs      []uint64          // cgroup IDs associated with this container
	// CgroupRoot is the cgroup2 path the runtime created for the container
	// (the component naming its full ID); every cgroup at or below it
	// belongs to the container. "" when the init path names no ID.
	CgroupRoot string
}

// ContainerEnricher maintains a live map of running containers, refreshed from
// the Docker or containerd socket every refreshInterval. It provides O(1)
// lookups by cgroup_id (the key available in every eBPF event): the init
// process's cgroups plus every cgroup below the container's runtime cgroup
// (see container_cgroup.go); an unknown ID triggers a rate-limited rescan.
//
// If the Docker socket is not available (non-containerized host), the enricher
// degrades gracefully — all Enrich calls return nil.
type ContainerEnricher struct {
	mu              sync.RWMutex
	byCgroupID      map[uint64]*ContainerInfo // cgroup_id → container
	byShortID       map[string]*ContainerInfo // short container ID → container
	client          *http.Client
	socketPath      string
	baseURL         string // "http://docker" for the unix socket; overridden in tests
	refreshInterval time.Duration
	available       bool

	// Cgroup ancestry. byRoot: CgroupRoot → container; unmatched:
	// IDs a rescan found outside every container. cgroupFS is the cgroup2
	// mount; walkHook (tests) observes rescans.
	byRoot            map[string]*ContainerInfo
	unmatched         map[uint64]struct{}
	cgroupFS          string
	rescanMu          sync.Mutex // serializes rescans; owns lastRescan
	lastRescan        time.Time
	minRescanInterval time.Duration
	walkHook          func()
}

const (
	defaultDockerSocket   = "/var/run/docker.sock"
	containerEnrichTTL    = 10 * time.Second
	containerReconcileTTL = 30 * time.Second // full refresh while the event stream is healthy
)

// containerSocketCandidates lists Docker-compatible unix sockets in probe
// order. containerd's own socket (/run/containerd/containerd.sock) is NOT
// here: it speaks containerd gRPC, not the Docker HTTP API — a constant
// pointing at it used to suggest a fallback that could never work. Podman and
// rootless Docker ship Docker-compatible endpoints and are probed instead.
// WAFIO_CONTAINER_SOCKET overrides the list entirely.
func containerSocketCandidates() []string {
	if s := strings.TrimSpace(os.Getenv("WAFIO_CONTAINER_SOCKET")); s != "" {
		return []string{s}
	}
	return []string{
		defaultDockerSocket,
		"/run/podman/podman.sock",
		os.Getenv("XDG_RUNTIME_DIR") + "/docker.sock", // rootless docker
	}
}

// NewContainerEnricher creates a ContainerEnricher that polls a
// Docker-compatible runtime socket. Call Start(ctx) to begin periodic refresh.
func NewContainerEnricher() *ContainerEnricher {
	e := &ContainerEnricher{
		byCgroupID:        make(map[uint64]*ContainerInfo),
		byShortID:         make(map[string]*ContainerInfo),
		byRoot:            make(map[string]*ContainerInfo),
		unmatched:         make(map[uint64]struct{}),
		cgroupFS:          cgroup2FS(),
		minRescanInterval: defaultMinRescanInterval,
		refreshInterval:   containerReconcileTTL,
	}
	e.setSocket(containerSocketCandidates()[0])
	return e
}

func (e *ContainerEnricher) setSocket(socket string) {
	e.socketPath = socket
	e.baseURL = "http://docker"
	e.client = &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socket)
			},
		},
	}
}

// rotateSocket advances to the next candidate socket (round-robin). Called on
// refresh failure so a host whose runtime appears later is still discovered.
func (e *ContainerEnricher) rotateSocket() {
	cands := containerSocketCandidates()
	if len(cands) <= 1 {
		return
	}
	for i, c := range cands {
		if c == e.socketPath {
			e.setSocket(cands[(i+1)%len(cands)])
			return
		}
	}
	e.setSocket(cands[0])
}

// Start keeps the container map fresh: an event stream against the runtime
// socket delivers start/destroy within milliseconds, and a slow
// periodic refresh reconciles anything the stream missed (disconnects,
// runtime restarts). The goroutines exit when ctx is cancelled.
func (e *ContainerEnricher) Start(ctx context.Context) {
	_ = e.refresh()

	go e.watchEvents(ctx)

	go func() {
		ticker := time.NewTicker(e.refreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = e.refresh()
			}
		}
	}()
}

// ── Docker event stream (sub-millisecond container discovery) ────────────────

// dockerEvent is a minimal subset of the GET /events NDJSON stream.
type dockerEvent struct {
	Action string `json:"Action"`
	Actor  struct {
		ID string `json:"ID"`
	} `json:"Actor"`
}

// watchEvents consumes the runtime's container event stream, reconnecting
// with backoff until ctx is cancelled. Every reconnect triggers a full
// refresh to repair state missed while disconnected.
func (e *ContainerEnricher) watchEvents(ctx context.Context) {
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		err := e.streamEvents(ctx)
		if ctx.Err() != nil {
			return
		}
		_ = e.refresh() // reconcile missed events
		if err != nil {
			time.Sleep(backoff)
			if backoff < 30*time.Second {
				backoff *= 2
			}
		} else {
			backoff = time.Second
		}
	}
}

// streamEvents subscribes to container lifecycle events. start/restart are
// enriched immediately (single inspect); die/destroy evict the entry. The
// connection stays open until the runtime or ctx ends.
func (e *ContainerEnricher) streamEvents(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET",
		e.baseURL+`/events?filters={"type":["container"]}`, nil)
	if err != nil {
		return err
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }() // read side of the body; a close error changes nothing
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("docker events API %d", resp.StatusCode)
	}

	dec := json.NewDecoder(bufio.NewReader(resp.Body))
	for {
		var ev dockerEvent
		if err := dec.Decode(&ev); err != nil {
			return err // stream ended or malformed — caller reconnects
		}
		switch ev.Action {
		case "start", "restart", "rename":
			e.enrichContainerNow(ev.Actor.ID)
		case "die", "destroy", "stop":
			e.evictContainer(ev.Actor.ID)
		}
	}
}

// dockerInspectFull covers the fields needed to enrich one container from a
// single inspect call (event path).
type dockerInspectFull struct {
	Name   string `json:"Name"`
	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	HostConfig struct {
		Privileged bool `json:"Privileged"`
	} `json:"HostConfig"`
	State struct {
		Pid int `json:"Pid"`
	} `json:"State"`
}

// enrichContainerNow upserts one container into the lookup maps right after
// a runtime start/restart event — no waiting for the next poll tick.
func (e *ContainerEnricher) enrichContainerNow(containerID string) {
	req, err := http.NewRequest("GET", e.baseURL+"/containers/"+containerID+"/json", nil)
	if err != nil {
		return
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return
	}
	defer func() { _ = resp.Body.Close() }() // read side of the body; a close error changes nothing
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil || resp.StatusCode != http.StatusOK {
		return
	}
	var ins dockerInspectFull
	if err := json.Unmarshal(body, &ins); err != nil {
		return
	}
	if len(containerID) < 12 {
		return
	}
	info := &ContainerInfo{
		ContainerID:    containerID,
		ContainerImage: ins.Config.Image,
		ContainerName:  strings.TrimPrefix(ins.Name, "/"),
		IsPrivileged:   ins.HostConfig.Privileged,
		Labels:         ins.Config.Labels,
		K8sPod:         ins.Config.Labels["io.kubernetes.pod.name"],
		K8sNamespace:   ins.Config.Labels["io.kubernetes.pod.namespace"],
	}
	if ins.State.Pid > 0 {
		initPath, initID := readInitCgroup(ins.State.Pid)
		info.CgroupIDs, info.CgroupRoot = containerCgroupIdentity(initPath, containerID, initID)
	}
	e.upsertContainer(info)
}

// upsertContainer adds or replaces one container: its init cgroups and the
// cgroups below its runtime root, walked before the lock is taken. A nested
// container already known keeps the cgroups below its own root.
func (e *ContainerEnricher) upsertContainer(info *ContainerInfo) {
	var below map[uint64]*ContainerInfo
	if info.CgroupRoot != "" {
		e.mu.RLock()
		roots := make(map[string]*ContainerInfo, len(e.byRoot)+1)
		for k, v := range e.byRoot {
			roots[k] = v
		}
		e.mu.RUnlock()
		roots[info.CgroupRoot] = info
		below = make(map[uint64]*ContainerInfo)
		found, _ := walkCgroupSubtree(e.cgroupFS, info.CgroupRoot, cgroupWalkBudget)
		for id, rel := range found {
			if containerForCgroupPath(rel, roots) == info {
				below[id] = info
			}
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.available = true
	if len(info.ContainerID) >= 12 {
		e.byShortID[info.ContainerID[:12]] = info
	}
	if info.CgroupRoot != "" {
		e.byRoot[info.CgroupRoot] = info
	}
	for _, cgroupID := range info.CgroupIDs {
		if cgroupID != 0 {
			e.byCgroupID[cgroupID] = info
		}
	}
	for id := range below {
		e.byCgroupID[id] = info
	}
	clear(e.unmatched)
}

// evictContainer removes a stopped/destroyed container from the lookup maps.
func (e *ContainerEnricher) evictContainer(containerID string) {
	if len(containerID) < 12 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	info, ok := e.byShortID[containerID[:12]]
	if !ok {
		return
	}
	delete(e.byShortID, containerID[:12])
	if e.byRoot[info.CgroupRoot] == info {
		delete(e.byRoot, info.CgroupRoot)
	}
	// Init cgroups and every sub-cgroup found by a walk.
	for cgroupID, cur := range e.byCgroupID {
		if cur == info {
			delete(e.byCgroupID, cgroupID)
		}
	}
}

// Enrich returns ContainerInfo for the given cgroup ID, or nil if the event
// is not from a container or the enricher is unavailable.
func (e *ContainerEnricher) Enrich(cgroupID uint64) *ContainerInfo {
	if cgroupID == 0 {
		return nil
	}
	e.mu.RLock()
	if !e.available {
		e.mu.RUnlock()
		return nil
	}
	info := e.byCgroupID[cgroupID]
	_, unmatched := e.unmatched[cgroupID]
	hasRoots := len(e.byRoot) > 0
	e.mu.RUnlock()
	if info != nil || unmatched || !hasRoots {
		return info
	}
	// Possibly a sub-cgroup created since the last walk.
	return e.rescanFor(cgroupID)
}

// EnrichByShortID returns ContainerInfo by short container ID (12 hex chars).
func (e *ContainerEnricher) EnrichByShortID(id string) *ContainerInfo {
	if len(id) < 12 {
		return nil
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.byShortID[id[:12]]
}

// Available reports whether Docker/containerd was detected on this host.
func (e *ContainerEnricher) Available() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.available
}

// refresh polls the Docker socket for currently running containers and rebuilds
// the internal lookup maps.
func (e *ContainerEnricher) refresh() error {
	containers, err := e.listContainers()
	if err != nil {
		// Socket dead: mark unavailable and advance to the next candidate so
		// the next tick probes it (runtime may have started or stopped).
		e.mu.Lock()
		e.available = false
		e.mu.Unlock()
		e.rotateSocket()
		return err
	}

	e.applySnapshot(containers)
	return nil
}

// applySnapshot replaces the lookup maps with a full container list: init
// cgroup IDs, runtime cgroup roots, and every cgroup below a root.
func (e *ContainerEnricher) applySnapshot(containers []*ContainerInfo) {
	newByCgroup := make(map[uint64]*ContainerInfo, len(containers))
	newByShortID := make(map[string]*ContainerInfo, len(containers))
	newByRoot := make(map[string]*ContainerInfo, len(containers))

	for _, info := range containers {
		key := info.ContainerID
		if len(key) >= 12 {
			newByShortID[key[:12]] = info
		}
		for _, cgroupID := range info.CgroupIDs {
			if cgroupID != 0 {
				newByCgroup[cgroupID] = info
			}
		}
		if info.CgroupRoot != "" {
			newByRoot[info.CgroupRoot] = info
		}
	}
	for id, owner := range e.walkRoots(newByRoot) {
		if _, exists := newByCgroup[id]; !exists {
			newByCgroup[id] = owner
		}
	}

	e.mu.Lock()
	e.byCgroupID = newByCgroup
	e.byShortID = newByShortID
	e.byRoot = newByRoot
	e.unmatched = make(map[uint64]struct{})
	e.available = true
	e.mu.Unlock()
}

// dockerContainer is a minimal subset of GET /containers/json response.
type dockerContainer struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	Image  string            `json:"Image"`
	Labels map[string]string `json:"Labels"`
	// HostConfig is used to check if container is privileged (requires inspect)
}

func (e *ContainerEnricher) listContainers() ([]*ContainerInfo, error) {
	req, err := http.NewRequest("GET", e.baseURL+"/containers/json?all=false", nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("docker socket: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() // read side of the body; a close error changes nothing

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("docker API %d: %s", resp.StatusCode, string(body))
	}

	var raw []dockerContainer
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("decode containers: %w", err)
	}

	result := make([]*ContainerInfo, 0, len(raw))
	for _, c := range raw {
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		info := &ContainerInfo{
			ContainerID:    c.ID,
			ContainerImage: c.Image,
			ContainerName:  name,
			Labels:         c.Labels,
			K8sPod:         c.Labels["io.kubernetes.pod.name"],
			K8sNamespace:   c.Labels["io.kubernetes.pod.namespace"],
		}
		// Attempt to get privileged status and cgroup info from container inspect.
		info.CgroupIDs, info.CgroupRoot = e.inspectCgroup(c.ID)
		info.IsPrivileged = e.inspectIsPrivileged(c.ID)
		result = append(result, info)
	}
	return result, nil
}

// dockerInspect is a minimal subset of the /containers/{id}/json response.
type dockerInspect struct {
	HostConfig struct {
		Privileged bool `json:"Privileged"`
	} `json:"HostConfig"`
	// cgroupID must be derived from /proc/<pid>/cgroup — Docker API doesn't expose it directly.
	// We use the container's first process PID if available.
	State struct {
		Pid int `json:"Pid"`
	} `json:"State"`
}

// inspectIsPrivileged checks if a container is running with --privileged.
func (e *ContainerEnricher) inspectIsPrivileged(containerID string) bool {
	req, err := http.NewRequest("GET", e.baseURL+"/containers/"+containerID+"/json", nil)
	if err != nil {
		return false
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }() // read side of the body; a close error changes nothing
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return false
	}
	var info dockerInspect
	if err := json.Unmarshal(body, &info); err != nil {
		return false
	}
	return info.HostConfig.Privileged
}

// inspectCgroup reads /proc/<pid>/cgroup for the container's init PID to
// extract cgroup IDs and the container's runtime cgroup root. This is
// the only reliable way to correlate eBPF cgroup_id with Docker containers
// since the Docker API doesn't expose cgroup IDs directly.
func (e *ContainerEnricher) inspectCgroup(containerID string) ([]uint64, string) {
	req, err := http.NewRequest("GET", e.baseURL+"/containers/"+containerID+"/json", nil)
	if err != nil {
		return nil, ""
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, ""
	}
	defer func() { _ = resp.Body.Close() }() // read side of the body; a close error changes nothing
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return nil, ""
	}
	var info dockerInspect
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, ""
	}

	if info.State.Pid <= 0 {
		return nil, ""
	}

	// The kernel cgroup_id in eBPF is the cgroupfs inode of the directory
	// named in /proc/<pid>/cgroup; mapped only when that path names the
	// container.
	initPath, initID := readInitCgroup(info.State.Pid)
	return containerCgroupIdentity(initPath, containerID, initID)
}
