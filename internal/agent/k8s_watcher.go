package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// K8sWatcher enriches container metadata with Kubernetes Pod context:
// pod name, namespace and service account, resolved in real time via the K8s
// watch API. No client-go: the in-cluster service account credentials + the
// streaming JSON watch endpoint are all that is needed, mirroring the
// zero-dependency Docker integration.
//
// When not running inside Kubernetes (no service account token), Start
// returns immediately and the enricher degrades gracefully.
type K8sWatcher struct {
	mu sync.RWMutex
	// containerID (64-hex) → pod context
	byContainer map[string]K8sPodContext
	client      *http.Client
	baseURL     string
	token       string
	watching    bool
}

// K8sPodContext is the Kubernetes metadata attached to trace events.
type K8sPodContext struct {
	PodName        string
	Namespace      string
	ServiceAccount string
	UID            string
}

const (
	k8sTokenFile  = "/var/run/secrets/kubernetes.io/serviceaccount/token" //nolint:gosec // G101: a file path, not a credential
	k8sCAFile     = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	k8sNsFile     = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
	k8sWatchRetry = 5 * time.Second
	// k8sListInterval is the pause between successful pod lists (the same
	// cadence as the Docker container poll).
	k8sListInterval = 10 * time.Second
)

// NewK8sWatcher probes for in-cluster credentials. Available() reports
// whether the watcher can reach the API server.
func NewK8sWatcher() *K8sWatcher {
	w := &K8sWatcher{byContainer: make(map[string]K8sPodContext)}
	token, err := os.ReadFile(k8sTokenFile)
	if err != nil {
		return w // not in a cluster (or token stripped)
	}
	w.token = strings.TrimSpace(string(token))

	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" {
		host = "kubernetes.default.svc"
		port = "443"
	}
	w.baseURL = "https://" + net_JoinHostPort(host, port)

	caPEM, err := os.ReadFile(k8sCAFile)
	if err != nil || len(caPEM) == 0 {
		return w // TLS root unknown; treat as unavailable
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return w
	}
	w.client = &http.Client{
		Timeout: 0, // watch streams stay open
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}
	return w
}

// Available reports whether in-cluster credentials were found.
func (w *K8sWatcher) Available() bool {
	return w != nil && w.client != nil && w.token != ""
}

// Watching reports whether the pod watch loop is live.
func (w *K8sWatcher) Watching() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.watching
}

// Lookup returns the pod context for a container ID (full or short), if known.
func (w *K8sWatcher) Lookup(containerID string) (K8sPodContext, bool) {
	if w == nil || len(containerID) < 12 {
		return K8sPodContext{}, false
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	ctx, ok := w.byContainer[containerID]
	if !ok {
		// Kubelet container IDs may differ from the Docker-visible one; try
		// the 64-char runtime ID and the 12-char short form interchangeably.
		ctx, ok = w.byContainer[containerID[:12]]
	}
	return ctx, ok
}

// k8sPod is the minimal /api/v1/pods item the watcher consumes.
type k8sPod struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
		UID       string `json:"uid"`
	} `json:"metadata"`
	Spec struct {
		ServiceAccountName string `json:"serviceAccountName"`
		Containers         []struct {
			Name string `json:"name"`
		} `json:"containers"`
	} `json:"spec"`
	Status struct {
		ContainerStatuses []struct {
			ContainerID string `json:"containerID"` // "docker://abcdef..."; prefix varies by runtime
		} `json:"containerStatuses"`
	} `json:"status"`
}

// Start launches the pod watch loop. It exits when ctx is cancelled.
func (w *K8sWatcher) Start(ctx context.Context) {
	if !w.Available() {
		return
	}
	go func() {
		for {
			if ctx.Err() != nil {
				return
			}
			err := w.watchPods(ctx)
			if ctx.Err() != nil {
				return
			}
			// watchPods is a full list that returns once read, so a success
			// waits like a failure: without the pause the loop re-listed
			// every pod back to back against the API server.
			wait := k8sListInterval
			if err != nil {
				wait = k8sWatchRetry
				log.Printf("[k8s] pod watch error: %v (retrying in %v)", err, wait)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
		}
	}()
}

// watchPods streams GET /api/v1/pods and rewrites the container → pod map on
// every snapshot (full-list watch: simple, self-healing, small at node scale
// when restricted to the local namespace — here we watch all pods visible to
// the service account, which on a node-restricted RBAC is the node's pods).
func (w *K8sWatcher) watchPods(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", w.baseURL+"/api/v1/pods", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+w.token)
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }() // read side of the body; a close error changes nothing
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("k8s api %d", resp.StatusCode)
	}

	var list struct {
		Items []k8sPod `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return err
	}

	fresh := make(map[string]K8sPodContext, len(list.Items))
	for _, pod := range list.Items {
		pctx := K8sPodContext{
			PodName:        pod.Metadata.Name,
			Namespace:      pod.Metadata.Namespace,
			ServiceAccount: pod.Spec.ServiceAccountName,
			UID:            pod.Metadata.UID,
		}
		for _, cs := range pod.Status.ContainerStatuses {
			if id := runtimeIDFromContainerID(cs.ContainerID); id != "" {
				fresh[id] = pctx
				fresh[id[:12]] = pctx
			}
		}
	}

	w.mu.Lock()
	w.byContainer = fresh
	w.watching = true
	w.mu.Unlock()
	return nil
}

// runtimeIDFromContainerID strips the "docker://" / "containerd://" scheme.
func runtimeIDFromContainerID(raw string) string {
	if i := strings.Index(raw, "://"); i >= 0 {
		raw = raw[i+3:]
	}
	if len(raw) < 12 {
		return ""
	}
	return raw
}

// net_JoinHostPort wraps IPv6 hosts in brackets.
func net_JoinHostPort(host, port string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}
