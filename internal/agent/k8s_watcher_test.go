package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// Watching reports whether the pod watch loop is live.
func (w *K8sWatcher) Watching() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.watching
}

// The enrichment both transports start (gRPC stream per connection,
// HTTP push per Run) includes the Kubernetes pod watcher, and a successful
// pod list is not repeated back to back.
func TestPushClientStartEnrichmentStartsK8sWatcher(t *testing.T) {
	var lists atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lists.Add(1)
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	defer srv.Close()
	k8s := &K8sWatcher{byContainer: make(map[string]K8sPodContext), baseURL: srv.URL, token: "test-token", client: srv.Client()}
	pc := &PushClient{k8sWatcher: k8s}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pc.startEnrichment(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for !k8s.Watching() {
		if time.Now().After(deadline) {
			t.Fatal("pod watcher not started")
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	if n := lists.Load(); n != 1 {
		t.Fatalf("%d pod lists within 200 ms, want 1 (no back-to-back re-list)", n)
	}
}

func TestK8sWatcherPodLookup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/pods" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`{"items":[{"metadata":{"name":"web-abc","namespace":"prod","uid":"u-1"},
			"spec":{"serviceAccountName":"web-sa"},
			"status":{"containerStatuses":[{"containerID":"containerd://abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"}]}}]}`))
	}))
	defer srv.Close()

	w := &K8sWatcher{byContainer: make(map[string]K8sPodContext), baseURL: srv.URL, token: "test-token"}
	w.client = srv.Client()

	if err := w.watchPods(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, ok := w.Lookup("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
	if !ok {
		t.Fatal("full container ID not found")
	}
	if ctx.PodName != "web-abc" || ctx.Namespace != "prod" || ctx.ServiceAccount != "web-sa" {
		t.Fatalf("pod context = %+v", ctx)
	}
	if short, ok := w.Lookup("abcdef12345678"); !ok || short.PodName != "web-abc" {
		t.Fatalf("short ID lookup failed: %+v ok=%v", short, ok)
	}
}

func TestK8sWatcherNilSafe(t *testing.T) {
	var w *K8sWatcher
	if w.Available() {
		t.Fatal("nil watcher must be unavailable")
	}
	if _, ok := w.Lookup("abcdef123456"); ok {
		t.Fatal("nil watcher must not resolve")
	}
	if _, ok := w.Lookup("short"); ok {
		t.Fatal("short IDs must never resolve")
	}
}
