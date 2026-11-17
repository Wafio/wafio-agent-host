package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLegacyPushFailureCountsDiscardedEvents(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer server.Close()
	pc := &PushClient{serverURL: server.URL, httpClient: server.Client()}
	pc.send(context.Background(), &PushPayload{TraceEvents: []json.RawMessage{json.RawMessage(`{}`), json.RawMessage(`{}`)}})
	if pc.httpSendFailures.Load() != 1 || pc.httpDroppedEvents.Load() != 2 || pc.httpAccepted.Load() != 0 {
		t.Fatal("legacy transport loss unreported")
	}
}
