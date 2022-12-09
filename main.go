package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapgrpc"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"github.com/mrincompetent/eviction-webhook/pkg/admission"
	"github.com/mrincompetent/eviction-webhook/pkg/eviction"
	httphelper "github.com/mrincompetent/eviction-webhook/pkg/http"
	loghelper "github.com/mrincompetent/eviction-webhook/pkg/log"
	tlshelper "github.com/mrincompetent/eviction-webhook/pkg/tls"
)

func main() {
	kubeconfig := flag.String("kubeconfig", "", "Path to kubeconfig")
	listenAddress := flag.String("listen-address", "127.0.0.1:6443", "Listen address")
	tlsCertPath := flag.String("tls.cert-path", "tls.crt", "")
	tlsKeyPath := flag.String("tls.key-path", "tls.key", "")
	logLevel := zap.LevelFlag("log.level", zap.InfoLevel, "Log level")
	flag.Parse()

	logCfg := zap.NewProductionConfig()
	logCfg.Level = zap.NewAtomicLevelAt(*logLevel)

	log, err := logCfg.Build()
	if err != nil {
		panic(fmt.Errorf("failed to create log: %w", err))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	restConfig, err := kubernetesRESTConfig(log, *kubeconfig)
	if err != nil {
		log.Panic("failed to get REST config", zap.Error(err))
	}

	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		log.Panic("failed to create Kubernetes client", zap.Error(err))
	}

	serverVersion, err := clientset.Discovery().ServerVersion()
	if err != nil {
		log.Panic("failed to get server version", zap.Error(err))
	}

	parsedServerVersion, err := semver.NewVersion(serverVersion.GitVersion)
	if err != nil {
		log.Panic("failed to parse server version", zap.Error(err))
	}

	informerFactory := informers.NewSharedInformerFactoryWithOptions(clientset, 24*time.Hour)

	scheme := runtime.NewScheme()
	schemeBuilder := runtime.NewSchemeBuilder(
		admissionv1.AddToScheme,
		corev1.AddToScheme,
	)

	if err := schemeBuilder.AddToScheme(scheme); err != nil {
		log.Panic("failed to add schemas", zap.Error(err))
	}

	registry := prometheus.NewRegistry()
	admissionServer := admission.NewServer(scheme)

	mux := httphelper.NewInstrumentedMux(registry)
	mux.HandleFunc("/validate-eviction",
		admissionServer.HandleV1AdmissionReview(
			eviction.Handler(eviction.NewStore(log, parsedServerVersion, informerFactory.Policy(), clientset.CoreV1()), 1024),
		),
	)
	mux.HandleFunc("/ready", func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
	})

	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{
		ErrorLog:          zapgrpc.NewLogger(log),
		Registry:          registry,
		Timeout:           5 * time.Second,
		EnableOpenMetrics: true,
	}))
	certWatcherMetricsVec := tlshelper.NewPrometheusCertificateWatcherMetricsVec(registry)
	certWatcher, err := tlshelper.NewCertificateWatcher(
		log,
		*tlsCertPath,
		*tlsKeyPath,
		&tlshelper.PrometheusCertificateWatcherMetrics{
			CertificatePath: *tlsCertPath,
			KeyPath:         *tlsKeyPath,
			MetricsVec:      certWatcherMetricsVec,
		},
	)
	if err != nil {
		log.Panic("failed to create certificate reloader", zap.Error(err))
	}

	httpServer := &http.Server{
		Handler: loghelper.RequestLogMiddleware(log, httphelper.RequestAwareTimeoutMiddleware(30*time.Second, mux)),
		Addr:    *listenAddress,
		TLSConfig: &tls.Config{
			GetCertificate: certWatcher.GetCertificate,
			MinVersion:     tls.VersionTLS13,
		},
		ReadTimeout:       1 * time.Second,
		WriteTimeout:      1 * time.Second,
		IdleTimeout:       30 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
	}

	informerFactory.Start(ctx.Done())

	syncRes := informerFactory.WaitForCacheSync(ctx.Done())
	for t, synced := range syncRes {
		if !synced {
			log.Panic("failed to wait for informer to be synced", zap.Stringer("informer", t))
		}
	}

	var g run.Group
	{
		g.Add(func() error {
			log.Info("Starting server", zap.String("listen-address", httpServer.Addr))

			if err := httpServer.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
				return err
			}
			log.Info("Stopped https server")

			return nil
		}, func(err error) {
			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()

			if err := httpServer.Shutdown(ctx); err != nil {
				log.Error("failed to perform clean shutdown of https server", zap.Error(err))
			}
		})
	}
	{
		ctx, cancel := context.WithCancel(ctx)
		g.Add(func() error {
			log.Info("Starting certificate watcher")

			if err := certWatcher.Run(ctx); err != nil {
				return err
			}
			log.Info("Stopped certificate watcher")

			return nil
		}, func(err error) {
			cancel()
		})
	}
	{
		// Signal handling
		ctx, cancel := context.WithCancel(ctx)
		g.Add(func() error {
			sigs := make(chan os.Signal, 1)
			signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
			select {
			case <-ctx.Done():
			case sig := <-sigs:
				log.Info("Received signal, shutting down", zap.Stringer("signal", sig))
			}

			return nil
		}, func(err error) {
			cancel()
		})
	}

	if err := g.Run(); err != nil {
		log.Error("group terminated with error", zap.Error(err))
	}
}

func kubernetesRESTConfig(log *zap.Logger, kubeconfig string) (*restclient.Config, error) {
	if kubeconfig == "" {
		log.Info("-kubeconfig wasn't defined, falling back to in-cluster configuration")

		return restclient.InClusterConfig()
	}

	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig},
		&clientcmd.ConfigOverrides{ClusterInfo: clientcmdapi.Cluster{}}).ClientConfig()
}
