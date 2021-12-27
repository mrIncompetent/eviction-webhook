package tls

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func TestNewCertificateWatcher(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1 * time.Hour),

		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
	require.NoError(t, err)

	dir, err := os.MkdirTemp(os.TempDir(), "cert-watcher")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, os.RemoveAll(dir)) })

	certPath := path.Join(dir, "cert.pem")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}), 0666))

	keyPath := path.Join(dir, "key.pem")
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}), 0666))

	watcher, err := NewCertificateWatcher(zaptest.NewLogger(t), certPath, keyPath)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go func() {
		assert.NoError(t, watcher.Run(ctx))
	}()

	assert.Eventually(t, func() bool {
		watcherCert, err := watcher.GetCertificate(nil)
		require.NoError(t, err)

		return assert.ObjectsAreEqual(derBytes, watcherCert.Certificate[0])
	}, 30*time.Second, 10*time.Millisecond)

	template = x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "test2"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1 * time.Hour),

		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err = x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}), 0666))

	assert.Eventually(t, func() bool {
		watcherCert, err := watcher.GetCertificate(nil)
		require.NoError(t, err)

		return assert.ObjectsAreEqual(derBytes, watcherCert.Certificate[0])
	}, 30*time.Second, 10*time.Millisecond)
}
