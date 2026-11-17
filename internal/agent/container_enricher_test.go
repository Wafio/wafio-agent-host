package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// fakeDockerRuntime serves the subset of the Docker HTTP API the enricher
// consumes: a streaming /events NDJSON feed and /containers/{id}/json.
func fakeDockerRuntime(t *testing.T, events <-chan string) (*ContainerEnricher, *map[string]bool) {
	t.Helper()
	seenDie := &map[string]bool{}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/events"):
			w.Header().Set("Content-Type", "application/json")
			fl := w.(http.Flusher)
			fl.Flush()
			for {
				select {
				case <-r.Context().Done():
					return
				case ev, ok := <-events:
					if !ok {
						return
					}
					w.Write([]byte(ev + "\n"))
					fl.Flush()
				}
			}
		case strings.HasPrefix(r.URL.Path, "/containers/"):
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"Name":"/evil","Config":{"Image":"crypto-miner:latest","Labels":{}},"HostConfig":{"Privileged":true},"State":{"Pid":4242}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() {
		srv.Close()
		ln.Close()
	})

	e := NewContainerEnricher()
	e.setHTTPClient(ln.Addr().String())
	return e, seenDie
}

func (e *ContainerEnricher) setHTTPClient(addr string) {
	e.baseURL = "http://" + addr
	e.socketPath = "tcp"
	e.client = &http.Client{Timeout: 5 * time.Second}
}

func TestContainerEventStreamEnrichAndEvict(t *testing.T) {
	events := make(chan string, 4)
	e, _ := fakeDockerRuntime(t, events)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.watchEvents(ctx)

	events <- `{"Action":"start","Actor":{"ID":"abcdef1234567890"}}`
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if info := e.EnrichByShortID("abcdef1234567890"); info != nil {
			if info.ContainerImage != "crypto-miner:latest" {
				t.Fatalf("image = %q", info.ContainerImage)
			}
			if !info.IsPrivileged {
				t.Fatal("privileged flag lost in event-path enrichment")
			}
			if info.ContainerName != "evil" {
				t.Fatalf("name = %q", info.ContainerName)
			}
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if e.EnrichByShortID("abcdef1234567890") == nil {
		t.Fatal("container not enriched from start event within deadline")
	}

	events <- `{"Action":"destroy","Actor":{"ID":"abcdef1234567890"}}`
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if e.EnrichByShortID("abcdef1234567890") == nil {
			return // evicted — success
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("container not evicted after destroy event")
}

func TestDockerEventDecode(t *testing.T) {
	r := bufio.NewReader(strings.NewReader(`{"Action":"start","Actor":{"ID":"abc123"}}` + "\n"))
	dec := json.NewDecoder(r)
	var ev dockerEvent
	if err := dec.Decode(&ev); err != nil {
		t.Fatal(err)
	}
	if ev.Action != "start" || ev.Actor.ID != "abc123" {
		t.Fatalf("decoded %+v", ev)
	}
}
