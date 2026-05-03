package api

import (
	"fmt"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
)

// Metrics holds the small set of counters Bulwark exposes at /metrics.
// Format is Prometheus text exposition (works with Grafana, VictoriaMetrics,
// etc.) — stdlib only, no client_golang dependency. The label vocabulary
// is intentionally tight: every cardinality explosion in production
// metrics traces back to "we labelled by user-supplied string" — so we
// label by enum-like values (action, level) and never by container name.
type Metrics struct {
	scansTotal       atomic.Int64
	dispatchByCh     counterMap // labels: notifier
	dispatchErrors   counterMap // labels: notifier
	applyByOutcome   counterMap // labels: outcome ∈ {success,rolled_back,failed}
	httpByStatus     counterMap // labels: route, code (Go status code class as 2xx/4xx/5xx)
	decisionsByOutc  counterMap // labels: decision ∈ {approved,rejected,forgot,cleared}
	rateLimited      atomic.Int64
}

// NewMetrics returns a fresh Metrics value. Safe for concurrent use.
func NewMetrics() *Metrics { return &Metrics{} }

// IncScan records one scan completion.
func (m *Metrics) IncScan() {
	if m == nil {
		return
	}
	m.scansTotal.Add(1)
}

// IncDispatch records the outcome of one dispatch attempt to a notifier.
// errored=true increments the error counter as well as the total.
func (m *Metrics) IncDispatch(channel string, errored bool) {
	if m == nil {
		return
	}
	m.dispatchByCh.add(channel)
	if errored {
		m.dispatchErrors.add(channel)
	}
}

// IncApply records the outcome of one apply attempt.
func (m *Metrics) IncApply(outcome string) {
	if m == nil {
		return
	}
	m.applyByOutcome.add(outcome)
}

// IncDecision records one approval-queue mutation.
func (m *Metrics) IncDecision(outcome string) {
	if m == nil {
		return
	}
	m.decisionsByOutc.add(outcome)
}

// IncHTTP records one served request bucketed into a 2xx/3xx/4xx/5xx class.
func (m *Metrics) IncHTTP(route string, status int) {
	if m == nil {
		return
	}
	m.httpByStatus.add(fmt.Sprintf("%s|%dxx", route, status/100))
}

// IncRateLimited records one request that was 429'd by the rate limiter.
func (m *Metrics) IncRateLimited() {
	if m == nil {
		return
	}
	m.rateLimited.Add(1)
}

// ServeHTTP renders the registered counters in Prometheus text format.
// Always 200 OK; never authed (industry convention for /metrics is
// network-layer protection, not application auth — which matters because
// the route is also probed by uptime monitors).
func (m *Metrics) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	if m == nil {
		_, _ = w.Write([]byte("# metrics not enabled\n"))
		return
	}
	out := w
	emitCounter(out, "bulwark_scans_total",
		"Total number of scan cycles completed by the daemon.",
		"counter", nil, m.scansTotal.Load())
	emitCounter(out, "bulwark_rate_limited_total",
		"Requests rejected by the per-IP rate limiter.",
		"counter", nil, m.rateLimited.Load())
	emitMap(out, "bulwark_dispatch_total",
		"Notifier dispatch outcomes by channel.",
		"counter", "channel", &m.dispatchByCh)
	emitMap(out, "bulwark_dispatch_errors_total",
		"Notifier dispatch errors by channel.",
		"counter", "channel", &m.dispatchErrors)
	emitMap(out, "bulwark_apply_total",
		"Apply outcomes by result (success / rolled_back / failed).",
		"counter", "outcome", &m.applyByOutcome)
	emitMap(out, "bulwark_decisions_total",
		"Approval-queue mutations by outcome.",
		"counter", "outcome", &m.decisionsByOutc)
	emitMap(out, "bulwark_http_total",
		"Served HTTP requests by route and 2xx/3xx/4xx/5xx class.",
		"counter", "", &m.httpByStatus) // composite key parsed in emitMap
}

func emitCounter(w http.ResponseWriter, name, help, kind string, _ map[string]string, value int64) {
	fmt.Fprintf(w, "# HELP %s %s\n", name, help)
	fmt.Fprintf(w, "# TYPE %s %s\n", name, kind)
	fmt.Fprintf(w, "%s %d\n", name, value)
}

// emitMap renders a counterMap as Prometheus text. When labelName is
// non-empty, each entry is emitted as `<name>{<labelName>="<key>"} <value>`.
// When labelName is empty, the key is interpreted as "<route>|<class>"
// and split into route + code labels — used by IncHTTP.
func emitMap(w http.ResponseWriter, name, help, kind, labelName string, m *counterMap) {
	fmt.Fprintf(w, "# HELP %s %s\n", name, help)
	fmt.Fprintf(w, "# TYPE %s %s\n", name, kind)
	for _, entry := range m.snapshot() {
		if labelName == "" {
			route, class := splitHTTPKey(entry.key)
			fmt.Fprintf(w, "%s{route=%q,code=%q} %d\n", name, route, class, entry.value)
			continue
		}
		fmt.Fprintf(w, "%s{%s=%q} %d\n", name, labelName, entry.key, entry.value)
	}
}

func splitHTTPKey(k string) (route, class string) {
	for i := len(k) - 1; i >= 0; i-- {
		if k[i] == '|' {
			return k[:i], k[i+1:]
		}
	}
	return k, ""
}

// counterMap is a tiny concurrency-safe int64-valued map. Entries are
// added on first use, never removed — since Bulwark's label cardinality
// is bounded (channels and routes are small enumerations), unbounded
// growth is not a concern.
type counterMap struct {
	mu sync.Mutex
	m  map[string]*atomic.Int64
}

func (c *counterMap) add(key string) {
	c.mu.Lock()
	if c.m == nil {
		c.m = make(map[string]*atomic.Int64)
	}
	v, ok := c.m[key]
	if !ok {
		v = &atomic.Int64{}
		c.m[key] = v
	}
	c.mu.Unlock()
	v.Add(1)
}

type counterEntry struct {
	key   string
	value int64
}

func (c *counterMap) snapshot() []counterEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]counterEntry, 0, len(c.m))
	for k, v := range c.m {
		out = append(out, counterEntry{key: k, value: v.Load()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key < out[j].key })
	return out
}
