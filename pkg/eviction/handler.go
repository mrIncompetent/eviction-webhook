package eviction

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"go.uber.org/zap"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/mrincompetent/eviction-webhook/pkg/admission"
)

type PDBInfoRetriever interface {
	GetPodDisruptionBudgetsForPod(*corev1.Pod) ([]metav1.Object, error)
	GetPod(ctx context.Context, namespace, name string) (*corev1.Pod, error)
}

const (
	namespace = "eviction-webhook.mrincompetent.io"

	annotationKeyEnableWebhook           = namespace + "/enable"
	annotationKeyWebhookEndpointHostname = namespace + "/hostname"
	annotationKeyWebhookEndpointPort     = namespace + "/port"
	annotationKeyWebhookEndpointScheme   = namespace + "/scheme"
	annotationKeyWebhookEndpointPath     = namespace + "/path"
)

var (
	v1EvictionGVK = metav1.GroupVersionKind{
		Group:   "policy",
		Version: "v1",
		Kind:    "Eviction",
	}

	v1beta1EvictionGVK = metav1.GroupVersionKind{
		Group:   "policy",
		Version: "v1beta",
		Kind:    "Eviction",
	}
)

var (
	errInvalidRequest    = errors.New("invalid request")
	errMultiplePDBsFound = errors.New("multiple PodDisruptionBudgets found that match the pod, this is unsupported")
)

func Handler(store PDBInfoRetriever, maxCheckResponseBodyLength int64) admission.Handler {
	return func(
		ctx context.Context,
		log *zap.Logger,
		req *admissionv1.AdmissionRequest,
	) (*admissionv1.AdmissionResponse, error) {
		log = log.Named("HandleEviction")

		if req.Kind != v1EvictionGVK && req.Kind != v1beta1EvictionGVK {
			return nil, fmt.Errorf(
				"%w. Expected either '%v' or '%v'. Got '%v'",
				errInvalidRequest,
				v1EvictionGVK.String(),
				v1beta1EvictionGVK.String(),
				req.Kind,
			)
		}

		pod, err := store.GetPod(ctx, req.Namespace, req.Name)
		if err != nil {
			if kerrors.IsNotFound(err) {
				log.Debug("Allowing eviction as pod could not be found")

				return &admissionv1.AdmissionResponse{
					Allowed: true,
				}, nil
			}

			return nil, fmt.Errorf("failed to load pod %s/%s: %w", req.Namespace, req.Name, err)
		}

		pdbs, err := store.GetPodDisruptionBudgetsForPod(pod)
		if err != nil {
			if kerrors.IsNotFound(err) {
				log.Debug("Allowing eviction as no PodDisruptionBudget could not be found")

				return &admissionv1.AdmissionResponse{
					Allowed: true,
				}, nil
			}

			return nil, fmt.Errorf("failed to load PodDisruptionBudgets for pod %s/%s: %w", req.Namespace, req.Name, err)
		}

		if len(pdbs) > 1 {
			// We follow what upstream does - it also simplifies our logic
			return nil, errMultiplePDBsFound
		}

		pdb := pdbs[0]
		log = log.With(zap.Any("poddisruptionbudget", pdb))

		if pdb.GetAnnotations()[annotationKeyEnableWebhook] != "true" {
			log.Debug("Allowing eviction as the PodDisruptionBudget doesn't use the webhook annotation")

			return &admissionv1.AdmissionResponse{
				Allowed: true,
			}, nil
		}

		hostname := pod.Status.PodIP
		if pdb.GetAnnotations()[annotationKeyWebhookEndpointHostname] != "" {
			hostname = strings.ReplaceAll(pdb.GetAnnotations()[annotationKeyWebhookEndpointHostname], "{{podname}}", pod.Name)
		}

		port := "80"
		if pdb.GetAnnotations()[annotationKeyWebhookEndpointPort] != "" {
			port = pdb.GetAnnotations()[annotationKeyWebhookEndpointPort]
		}

		scheme := "http"
		if pdb.GetAnnotations()[annotationKeyWebhookEndpointScheme] != "" {
			scheme = pdb.GetAnnotations()[annotationKeyWebhookEndpointScheme]
		}

		path := "/eviction-check"
		if pdb.GetAnnotations()[annotationKeyWebhookEndpointPath] != "" {
			path = strings.ReplaceAll(pdb.GetAnnotations()[annotationKeyWebhookEndpointPath], "{{podname}}", pod.Name)
		}

		url := fmt.Sprintf("%s://%s:%s%s", scheme, hostname, port, path)

		log = log.With(zap.String("check-url", url))

		checkReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to build request: %w", err)
		}

		response, err := http.DefaultClient.Do(checkReq)
		if err != nil {
			return nil, fmt.Errorf("request failed: %w", err)
		}
		defer response.Body.Close()

		if response.StatusCode == http.StatusOK {
			log.Debug("Allowing eviction as the check succeeded")

			return &admissionv1.AdmissionResponse{
				Allowed: true,
			}, nil
		}

		body, err := io.ReadAll(io.LimitReader(response.Body, maxCheckResponseBodyLength))
		if err != nil {
			log.Error("failed to read response body", zap.Error(err))
		}

		message := fmt.Sprintf(
			"PodDisruptionBudget webhook check failed. Endpoint returned status code %d. Response body:\n'%s'",
			response.StatusCode,
			string(body),
		)

		return &admissionv1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Status:  metav1.StatusFailure,
				Message: message,
				Reason:  metav1.StatusReasonTooManyRequests,
				Code:    http.StatusOK,
			},
		}, nil
	}
}
