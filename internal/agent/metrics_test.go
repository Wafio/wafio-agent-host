package agent

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wafio/wafio-cp-backend/shared/metrics"
)

func TestHostMetricsRender(t *testing.T) {
	reg := metrics.NewRegistry()
	RegisterHostMetrics(reg)
	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()
	for _, w := range []string{"wafio_host_telemetry_send_failures_total", "wafio_host_telemetry_pending{unit=\"batches\"}"} {
		if !strings.Contains(body, w) {
			t.Errorf("host: missing %s", w)
		}
	}
	// The host agent runs no WAF pipeline and no IP jail.
	if strings.Contains(body, "wafio_waf_jail_refused") {
		t.Error("host: wafio_waf_jail_refused must not be registered")
	}
	if !strings.HasSuffix(body, "# EOF\n") {
		t.Error("host: no # EOF")
	}
}
