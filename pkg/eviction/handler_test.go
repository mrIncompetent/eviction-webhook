package eviction

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func newPDBStoreStub(tb testing.TB) *pdbStoreStub {
	return &pdbStoreStub{tb: tb}
}

type pdbStoreStub struct {
	tb testing.TB

	getPodDisruptionBudgetsForPodFunc func(*corev1.Pod) ([]metav1.Object, error)
	getPodFunc                        func(ctx context.Context, namespace, name string) (*corev1.Pod, error)
}

func (s *pdbStoreStub) GetPodDisruptionBudgetsForPod(pod *corev1.Pod) ([]metav1.Object, error) {
	if s.getPodDisruptionBudgetsForPodFunc == nil {
		s.tb.Fatal("GetPodDisruptionBudgetsForPod called but not defined")
	}

	return s.getPodDisruptionBudgetsForPodFunc(pod)
}

func (s *pdbStoreStub) GetPod(ctx context.Context, namespace, name string) (*corev1.Pod, error) {
	if s.getPodFunc == nil {
		s.tb.Fatal("GetPod called but not defined")
	}

	return s.getPodFunc(ctx, namespace, name)
}

func TestHandler(t *testing.T) {
	t.Run("invalid request", func(t *testing.T) {
		store := newPDBStoreStub(t)
		handleRequest := Handler(store, 1024)

		_, err := handleRequest(context.Background(), zaptest.NewLogger(t), &admissionv1.AdmissionRequest{
			Kind: metav1.GroupVersionKind{
				Group:   "some-group",
				Version: "some-version",
				Kind:    "some-kind",
			},
		})
		assert.EqualError(t, err, "invalid request. Expected either 'policy/v1, Kind=Eviction' or 'policy/v1beta, Kind=Eviction'. Got 'some-group/some-version, Kind=some-kind'")
	})

	t.Run("allow request as the pod does not exist", func(t *testing.T) {
		store := newPDBStoreStub(t)
		store.getPodFunc = func(ctx context.Context, namespace, name string) (*corev1.Pod, error) {
			return nil, kerrors.NewNotFound(corev1.Resource("pod"), fmt.Sprintf("%s/%s", namespace, name))
		}
		handleRequest := Handler(store, 1024)

		res, err := handleRequest(context.Background(), zaptest.NewLogger(t), &admissionv1.AdmissionRequest{
			Kind:      v1EvictionGVK,
			Name:      "pod-1",
			Namespace: "default",
		})
		assert.NoError(t, err)
		assert.True(t, res.Allowed)
	})

	t.Run("failed to load pod", func(t *testing.T) {
		store := newPDBStoreStub(t)
		store.getPodFunc = func(ctx context.Context, namespace, name string) (*corev1.Pod, error) {
			return nil, errors.New("something went wrong")
		}
		handleRequest := Handler(store, 1024)

		_, err := handleRequest(context.Background(), zaptest.NewLogger(t), &admissionv1.AdmissionRequest{
			Kind:      v1EvictionGVK,
			Name:      "pod-1",
			Namespace: "default",
		})
		assert.EqualError(t, err, "failed to load pod default/pod-1: something went wrong")
	})

	t.Run("allow request as the pdb does not exist", func(t *testing.T) {
		store := newPDBStoreStub(t)
		store.getPodFunc = func(ctx context.Context, namespace, name string) (*corev1.Pod, error) {
			return &corev1.Pod{}, nil
		}
		store.getPodDisruptionBudgetsForPodFunc = func(pod *corev1.Pod) ([]metav1.Object, error) {
			return nil, kerrors.NewNotFound(policyv1.Resource("poddisruptionbudget"), "")
		}
		handleRequest := Handler(store, 1024)

		res, err := handleRequest(context.Background(), zaptest.NewLogger(t), &admissionv1.AdmissionRequest{
			Kind:      v1EvictionGVK,
			Name:      "pod-1",
			Namespace: "default",
		})
		assert.NoError(t, err)
		assert.True(t, res.Allowed)
	})

	t.Run("failed to load pdb", func(t *testing.T) {
		store := newPDBStoreStub(t)
		store.getPodFunc = func(ctx context.Context, namespace, name string) (*corev1.Pod, error) {
			return &corev1.Pod{}, nil
		}
		store.getPodDisruptionBudgetsForPodFunc = func(pod *corev1.Pod) ([]metav1.Object, error) {
			return nil, errors.New("something went wrong")
		}
		handleRequest := Handler(store, 1024)

		_, err := handleRequest(context.Background(), zaptest.NewLogger(t), &admissionv1.AdmissionRequest{
			Kind:      v1EvictionGVK,
			Name:      "pod-1",
			Namespace: "default",
		})
		assert.EqualError(t, err, "failed to load PodDisruptionBudgets for pod default/pod-1: something went wrong")
	})

	t.Run("multiple pdbs", func(t *testing.T) {
		store := newPDBStoreStub(t)
		store.getPodFunc = func(ctx context.Context, namespace, name string) (*corev1.Pod, error) {
			return &corev1.Pod{}, nil
		}
		store.getPodDisruptionBudgetsForPodFunc = func(pod *corev1.Pod) ([]metav1.Object, error) {
			return []metav1.Object{
				&policyv1.PodDisruptionBudget{},
				&policyv1.PodDisruptionBudget{},
			}, nil
		}
		handleRequest := Handler(store, 1024)

		_, err := handleRequest(context.Background(), zaptest.NewLogger(t), &admissionv1.AdmissionRequest{
			Kind:      v1EvictionGVK,
			Name:      "pod-1",
			Namespace: "default",
		})
		assert.EqualError(t, err, "multiple PodDisruptionBudgets found that match the pod, this is unsupported")
	})

	t.Run("pdb without annotation", func(t *testing.T) {
		store := newPDBStoreStub(t)
		store.getPodFunc = func(ctx context.Context, namespace, name string) (*corev1.Pod, error) {
			return &corev1.Pod{}, nil
		}
		store.getPodDisruptionBudgetsForPodFunc = func(pod *corev1.Pod) ([]metav1.Object, error) {
			return []metav1.Object{
				&policyv1.PodDisruptionBudget{},
			}, nil
		}
		handleRequest := Handler(store, 1024)

		res, err := handleRequest(context.Background(), zaptest.NewLogger(t), &admissionv1.AdmissionRequest{
			Kind:      v1EvictionGVK,
			Name:      "pod-1",
			Namespace: "default",
		})
		assert.NoError(t, err)
		assert.True(t, res.Allowed)
	})

	t.Run("response code", func(t *testing.T) {
		responseCodeTests := []struct {
			Code            int
			Allow           bool
			ExpectedMessage string
		}{
			{
				Code:  http.StatusOK,
				Allow: true,
			},
			{
				Code:            http.StatusTooManyRequests,
				Allow:           false,
				ExpectedMessage: "PodDisruptionBudget webhook check failed. Endpoint returned status code 429. Response body:\n'some response message'",
			},
		}
		for _, test := range responseCodeTests {
			t.Run(fmt.Sprintf("allow %d, %v", test.Code, test.Allow), func(t *testing.T) {
				var receivedRequest *http.Request
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					receivedRequest = r
					w.WriteHeader(test.Code)
					_, err := w.Write([]byte("some response message"))
					require.NoError(t, err)
				}))
				defer ts.Close()

				u, err := url.Parse(ts.URL)
				require.NoError(t, err)

				annotations := map[string]string{
					annotationKeyEnableWebhook:           "true",
					annotationKeyWebhookEndpointScheme:   u.Scheme,
					annotationKeyWebhookEndpointHostname: u.Hostname(),
					annotationKeyWebhookEndpointPort:     u.Port(),
					annotationKeyWebhookEndpointPath:     "/healthy",
				}

				store := newPDBStoreStub(t)
				store.getPodFunc = func(ctx context.Context, namespace, name string) (*corev1.Pod, error) {
					return &corev1.Pod{}, nil
				}
				store.getPodDisruptionBudgetsForPodFunc = func(pod *corev1.Pod) ([]metav1.Object, error) {
					return []metav1.Object{
						&policyv1.PodDisruptionBudget{
							ObjectMeta: metav1.ObjectMeta{
								Annotations: annotations,
							},
						},
					}, nil
				}
				handleRequest := Handler(store, 1024)

				res, err := handleRequest(context.Background(), zaptest.NewLogger(t), &admissionv1.AdmissionRequest{
					Kind:      v1EvictionGVK,
					Name:      "pod-1",
					Namespace: "default",
				})
				assert.NoError(t, err)
				assert.Equal(t, test.Allow, res.Allowed)
				if !res.Allowed {
					assert.Equal(t, test.ExpectedMessage, res.Result.Message)
				}

				require.NotNil(t, receivedRequest)
				assert.Equal(t, annotations[annotationKeyWebhookEndpointPath], receivedRequest.URL.Path)
			})
		}
	})
}
