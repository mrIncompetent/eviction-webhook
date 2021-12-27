package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

func NewCertificateWatcher(log *zap.Logger, certPath, keyPath string) (*CertificateWatcher, error) {
	cw := &CertificateWatcher{
		log: log.Named("CertificateWatcher").With(
			zap.Any("certificate-path", certPath),
			zap.Any("key-path", keyPath),
		),
		certPath: certPath,
		keyPath:  keyPath,
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

			cw.log.Info("Watcher event", zap.Any("event", event))
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
		return err
	}

	cw.certLock.Lock()
	defer cw.certLock.Unlock()
	cw.cert = &cert

	return nil
}

func (cw *CertificateWatcher) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cw.certLock.RLock()
	defer cw.certLock.RUnlock()

	return cw.cert, nil
}
