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

	latency          *prometheus.HistogramVec
	inFlightRequests *prometheus.GaugeVec
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
		i.inFlightRequests.With(prometheus.Labels{
			"handler": r.URL.Path,
			"method":  r.Method,
		}).Inc()
		defer i.inFlightRequests.With(prometheus.Labels{
			"handler": r.URL.Path,
			"method":  r.Method,
		}).Dec()

		ww := &statusCaptcher{
			next: w,
		}
		next.ServeHTTP(ww, r)

		i.latency.With(prometheus.Labels{
			"handler": r.URL.Path,
			"method":  r.Method,
			"code":    strconv.Itoa(ww.statusCode),
		}).Observe(time.Since(start).Seconds())
	})
}

func (i *InstrumentedMux) Handler() http.Handler {
	return i.ServeMux
}

func NewInstrumentedMux(reg prometheus.Registerer) *InstrumentedMux {
	latency := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "http_request_duration_seconds",
		Help:    "A histogram of latencies for requests.",
		Buckets: prometheus.DefBuckets,
	}, []string{"handler", "method", "code"})
	reg.MustRegister(latency)

	inFlightRequests := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "http_requests_in_flight",
		Help: "A gauge of requests currently being served by the wrapped handler.",
	}, []string{"handler", "method"})
	reg.MustRegister(inFlightRequests)

	return &InstrumentedMux{
		ServeMux: http.NewServeMux(),

		latency:          latency,
		inFlightRequests: inFlightRequests,
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
