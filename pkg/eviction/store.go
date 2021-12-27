package eviction

import (
	"context"
	"fmt"

	"github.com/Masterminds/semver/v3"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers/policy"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	policyv1lister "k8s.io/client-go/listers/policy/v1"
	policyv1beta1lister "k8s.io/client-go/listers/policy/v1beta1"
)

var (
	pdbGraduationVersion = semver.MustParse("v1.21")
)

func NewStore(
	log *zap.Logger,
	serverVersion *semver.Version,
	policyInformers policy.Interface,
	corev1client corev1client.CoreV1Interface,
) PDBInfoRetriever {
	if serverVersion.LessThan(pdbGraduationVersion) {
		log.Info("Using policy v1beta APIs", zap.Any("server-version", serverVersion))

		return &pdbStoreV1beta1{
			pdbLister:    policyInformers.V1beta1().PodDisruptionBudgets().Lister(),
			corev1Client: corev1client,
		}
	}

	log.Info("Using policy v1 APIs", zap.Any("server-version", serverVersion))

	return &pdbStoreV1{
		pdbLister:    policyInformers.V1().PodDisruptionBudgets().Lister(),
		corev1Client: corev1client,
	}
}

type pdbStoreV1 struct {
	pdbLister    policyv1lister.PodDisruptionBudgetLister
	corev1Client corev1client.CoreV1Interface
}

func (p *pdbStoreV1) GetPodDisruptionBudgetsForPod(pod *corev1.Pod) ([]metav1.Object, error) {
	pdbs, err := p.pdbLister.GetPodPodDisruptionBudgets(pod)
	if err != nil {
		return nil, wrapPDBError(err, pod)
	}

	res := make([]metav1.Object, len(pdbs))
	for i := range pdbs {
		res[i] = pdbs[i]
	}

	return res, nil
}

func (p *pdbStoreV1) GetPod(ctx context.Context, namespace, name string) (*corev1.Pod, error) {
	return p.corev1Client.Pods(namespace).Get(ctx, name, metav1.GetOptions{})
}

type pdbStoreV1beta1 struct {
	pdbLister    policyv1beta1lister.PodDisruptionBudgetLister
	corev1Client corev1client.CoreV1Interface
}

func (p *pdbStoreV1beta1) GetPodDisruptionBudgetsForPod(pod *corev1.Pod) ([]metav1.Object, error) {
	pdbs, err := p.pdbLister.GetPodPodDisruptionBudgets(pod)
	if err != nil {
		return nil, wrapPDBError(err, pod)
	}

	res := make([]metav1.Object, len(pdbs))
	for i := range pdbs {
		res[i] = pdbs[i]
	}

	return res, nil
}

func (p *pdbStoreV1beta1) GetPod(ctx context.Context, namespace, name string) (*corev1.Pod, error) {
	return p.corev1Client.Pods(namespace).Get(ctx, name, metav1.GetOptions{})
}

func wrapPDBError(err error, pod *corev1.Pod) error {
	//nolint: goerr113
	noPDBError := fmt.Errorf(
		"could not find PodDisruptionBudget for pod %s in namespace %s with labels: %v",
		pod.Name,
		pod.Namespace,
		pod.Labels,
	)
	if err.Error() == noPDBError.Error() {
		return kerrors.NewNotFound(policyv1.Resource("poddisruptionbudget"), "")
	}

	return err
}
