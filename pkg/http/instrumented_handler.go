package http

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// InstrumentedMux wraps a http.ServeMux with Prometheus instrumentation.
// It ensures that registered handlers are instrumented and avoids a cardinality explosion for unregistered handlers.
// Otherwise, a malicious actor could spam the server with arbitrary paths and blow up the cardinality of the metrics.
type InstrumentedMux struct {
	*http.ServeMux

	metrics MuxMetrics
}

type MuxMetrics interface {
	ObserverLatency(handler, method string, code int, d time.Duration)
	IncInFlightRequests(handler, method string)
	DecInFlightRequests(handler, method string)
}

func (i *InstrumentedMux) HandleFunc(pattern string, handler http.HandlerFunc) {
	i.ServeMux.Handle(pattern, i.handleInstrumented(handler))
}

func (i *InstrumentedMux) Handle(pattern string, handler http.Handler) {
	i.ServeMux.Handle(pattern, i.handleInstrumented(handler))
}

func (i *InstrumentedMux) handleInstrumented(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		i.metrics.IncInFlightRequests(r.URL.Path, r.Method)
		defer i.metrics.DecInFlightRequests(r.URL.Path, r.Method)

		ww := &statusCaptcher{
			next: w,
		}
		next.ServeHTTP(ww, r)

		i.metrics.ObserverLatency(r.URL.Path, r.Method, ww.statusCode, time.Since(start))
	})
}

func (i *InstrumentedMux) Handler() http.Handler {
	return i.ServeMux
}

func NewInstrumentedMux(metrics MuxMetrics) *InstrumentedMux {
	return &InstrumentedMux{
		ServeMux: http.NewServeMux(),
		metrics:  metrics,
	}
}

type statusCaptcher struct {
	statusCode int
	next       http.ResponseWriter
}

func (s *statusCaptcher) Header() http.Header {
	return s.next.Header()
}

func (s *statusCaptcher) Write(b []byte) (int, error) {
	return s.next.Write(b)
}

func (s *statusCaptcher) WriteHeader(statusCode int) {
	s.statusCode = statusCode
	s.next.WriteHeader(statusCode)
}

func NewPrometheusMuxMetrics(reg prometheus.Registerer) *PrometheusMuxMetrics {
	m := &PrometheusMuxMetrics{
		latency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "A histogram of latencies for requests.",
			Buckets: prometheus.DefBuckets,
		}, []string{"handler", "method", "code"}),
		inFlightRequests: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "http_requests_in_flight",
			Help: "A gauge of requests currently being served by the wrapped handler.",
		}, []string{"handler", "method"}),
	}

	reg.MustRegister(m.latency)
	reg.MustRegister(m.inFlightRequests)

	return m
}

type PrometheusMuxMetrics struct {
	latency          *prometheus.HistogramVec
	inFlightRequests *prometheus.GaugeVec
}

func (m *PrometheusMuxMetrics) ObserverLatency(handler, method string, code int, d time.Duration) {
	m.latency.With(prometheus.Labels{
		"handler": handler,
		"method":  method,
		"code":    strconv.Itoa(code),
	}).Observe(d.Seconds())
}

func (m *PrometheusMuxMetrics) IncInFlightRequests(handler, method string) {
	m.inFlightRequests.With(prometheus.Labels{
		"handler": handler,
		"method":  method,
	}).Inc()
}

func (m *PrometheusMuxMetrics) DecInFlightRequests(handler, method string) {
	m.inFlightRequests.With(prometheus.Labels{
		"handler": handler,
		"method":  method,
	}).Dec()
}
