package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func NewCertificateWatcher(log *zap.Logger, certPath, keyPath string, metrics CertificateWatcherMetrics) (*CertificateWatcher, error) {
	cw := &CertificateWatcher{
		log: log.Named("CertificateWatcher").With(
			zap.Any("certificate-path", certPath),
			zap.Any("key-path", keyPath),
		),
		certPath: certPath,
		keyPath:  keyPath,
		metrics:  metrics,
	}

	if err := cw.reload(); err != nil {
		return nil, fmt.Errorf("failed to load certificates: %w", err)
	}

	return cw, nil
}

type CertificateWatcher struct {
	log *zap.Logger

	cert     *tls.Certificate
	certLock sync.RWMutex

	certPath string
	keyPath  string

	metrics CertificateWatcherMetrics
}

func (cw *CertificateWatcher) Run(ctx context.Context) error {
	reloadChan := make(chan bool, 1)
	defer close(reloadChan)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create filewatcher: %w", err)
	}
	defer watcher.Close()

	if err := watcher.Add(cw.certPath); err != nil {
		return fmt.Errorf("failed to watch %s: %w", cw.certPath, err)
	}

	if err := watcher.Add(cw.keyPath); err != nil {
		return fmt.Errorf("failed to watch %s: %w", cw.certPath, err)
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			event, ok := <-watcher.Events
			if !ok {
				return
			}

			cw.log.Info("Watcher event", zap.Object("event", zapcore.ObjectMarshalerFunc(func(enc zapcore.ObjectEncoder) error {
				enc.AddString("name", event.Name)
				enc.AddString("op", event.Op.String())
				return nil
			})))
			reloadChan <- true
		}
	}()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			if _, ok := <-reloadChan; !ok {
				return
			}

			if err := cw.reload(); err != nil {
				cw.log.Error("failed to reload certificate", zap.Error(err))

				go func() {
					time.Sleep(1 * time.Second)
					reloadChan <- true
				}()
			} else {
				cw.log.Info("Reloaded certificates")
			}
		}
	}()

	<-ctx.Done()

	return nil
}

func (cw *CertificateWatcher) reload() error {
	cert, err := tls.LoadX509KeyPair(cw.certPath, cw.keyPath)
	if err != nil {
		cw.metrics.ReloadFailure(CertificateWatcherReloadFailureReasonLoadKeypair)
		return fmt.Errorf("failed to load certificate: %w", err)
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		cw.metrics.ReloadFailure(CertificateWatcherReloadFailureReasonParseCertificate)
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	cw.certLock.Lock()
	defer cw.certLock.Unlock()
	cw.cert = &cert

	cw.metrics.ReloadSuccess()
	cw.metrics.CertificateExpirationTimestamp(x509Cert.NotAfter)

	return nil
}

func (cw *CertificateWatcher) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cw.certLock.RLock()
	defer cw.certLock.RUnlock()

	return cw.cert, nil
}

type CertificateWatcherReloadFailureReason string

const (
	// CertificateWatcherReloadFailureReasonParseCertificate is used when the certificate could not be parsed.
	CertificateWatcherReloadFailureReasonParseCertificate CertificateWatcherReloadFailureReason = "parse_certificate"
	// CertificateWatcherReloadFailureReasonLoadKeypair is used when either the certificate or the key could not be loaded.
	CertificateWatcherReloadFailureReasonLoadKeypair CertificateWatcherReloadFailureReason = "load_keypair"
)

// CertificateWatcherMetrics defines functions to emit metrics for the certificate watcher.
type CertificateWatcherMetrics interface {
	// ReloadSuccess is called when the certificate watcher successfully reloads the certificate.
	ReloadSuccess()
	// ReloadFailure is called when the certificate watcher fails to reload the certificate.
	ReloadFailure(reason CertificateWatcherReloadFailureReason)
	// CertificateExpirationTimestamp is called when the certificate watcher loads/reloads the certificate.
	CertificateExpirationTimestamp(time.Time)
}

type NoOpCertificateWatcherMetrics struct{}

func (NoOpCertificateWatcherMetrics) ReloadSuccess() {}

func (NoOpCertificateWatcherMetrics) ReloadFailure(reason CertificateWatcherReloadFailureReason) {}

func (NoOpCertificateWatcherMetrics) CertificateExpirationTimestamp(time.Time) {}

type PrometheusCertificateWatcherMetricsVec struct {
	reloadSuccessCounter           *prometheus.CounterVec
	reloadFailureCounter           *prometheus.CounterVec
	certificateExpirationTimestamp *prometheus.GaugeVec
}

func NewPrometheusCertificateWatcherMetricsVec(reg prometheus.Registerer) *PrometheusCertificateWatcherMetricsVec {
	labelNames := []string{
		"certificate_path",
		"key_path",
	}

	m := &PrometheusCertificateWatcherMetricsVec{
		reloadSuccessCounter: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "cert_watcher_reload_success_total",
			Help: "Total number of successful certificate reloads.",
		}, labelNames),
		reloadFailureCounter: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "cert_watcher_reload_failure_total",
			Help: "Total number of failed certificate reloads.",
		}, append(labelNames, "reason")),
		certificateExpirationTimestamp: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "cert_watcher_certificate_expiration_timestamp",
			Help: "Timestamp of the certificate expiration.",
		}, labelNames),
	}

	reg.MustRegister(m.reloadSuccessCounter, m.reloadFailureCounter, m.certificateExpirationTimestamp)

	return m
}

type PrometheusCertificateWatcherMetrics struct {
	CertificatePath string
	KeyPath         string

	MetricsVec *PrometheusCertificateWatcherMetricsVec
}

func (m *PrometheusCertificateWatcherMetrics) ReloadSuccess() {
	m.MetricsVec.reloadSuccessCounter.With(prometheus.Labels{
		"certificate_path": m.CertificatePath,
		"key_path":         m.KeyPath,
	}).Inc()
}

func (m *PrometheusCertificateWatcherMetrics) ReloadFailure(reason CertificateWatcherReloadFailureReason) {
	m.MetricsVec.reloadFailureCounter.With(prometheus.Labels{
		"certificate_path": m.CertificatePath,
		"key_path":         m.KeyPath,
		"reason":           string(reason),
	}).Inc()
}

func (m *PrometheusCertificateWatcherMetrics) CertificateExpirationTimestamp(t time.Time) {
	m.MetricsVec.certificateExpirationTimestamp.With(prometheus.Labels{
		"certificate_path": m.CertificatePath,
		"key_path":         m.KeyPath,
	}).Set(float64(t.Unix()))
}
