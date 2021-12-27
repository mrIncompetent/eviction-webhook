# Kubernetes Eviction Admission Controller

This is an admission controller for Kubernetes that validates eviction requests. It allows you to specify annotations for your PodDisruptionBudget (PDB), which will cause the admission controller to call an endpoint on the pod before allowing the eviction to take place.

The admission controller supports the following annotations:
- `eviction-webhook.mrincompetent.io/enable`: Whether to enable the admission controller for this PDB. Valid values are `true` and `false`. If this annotation is not specified, the default value is `false`.
- `eviction-webhook.mrincompetent.io/hostname`: The hostname of the endpoint that the admission controller should call. This annotation supports the template variable `{podname}`, which will be replaced with the name of the pod. If this annotation is not specified, the default value is the pod's IP address.
- `eviction-webhook.mrincompetent.io/port`: The port of the endpoint that the admission controller should call. If this annotation is not specified, the default value is 80.
- `eviction-webhook.mrincompetent.io/scheme`:  The scheme (i.e. HTTP or HTTPS) of the endpoint that the admission controller should call. If this annotation is not specified, the default value is HTTP.
- `eviction-webhook.mrincompetent.io/path`: The path of the endpoint that the admission controller should call. This annotation supports the template variable `{podname}`, which will be replaced with the name of the pod. If this annotation is not specified, the default value is `/`.

If the endpoint responds with a 200 status code, the eviction will be allowed to proceed. If it responds with any other status code, the eviction will be denied. This can be used to protect workload from outages if the cluster-state is not healthy, but all pods are.
Upstream issue: https://github.com/kubernetes/kubernetes/issues/44145

## Installation

To install the admission controller, follow these steps:
1. Install cert-manager: https://cert-manager.io/docs/installation/kubernetes/
2. Clone the repository
3. Deploy the admission controller to your cluster: `kubectl apply -f admission-controller.yaml`
4. Verify it's running: `kubectl -n eviction-webhook get pods`

After the deployment is complete, the admission controller will be installed and ready to use.

## Usage

To use the admission controller, simply add the relevant annotations to any PodDisruptionBudget that you want to protect from eviction. The values of the annotations should specify the endpoint that the admission controller should call before allowing the eviction to take place.

For example, if your pod provides an endpoint at http://my-pod-ip/eviction-hook on port `8080`, you would add the following annotations to your PodDisruptionBudget:
```yaml
annotations:
  eviction-webhook.mrincompetent.io/enable: "true"
  eviction-webhook.mrincompetent.io/port: "8080"
  eviction-webhook.mrincompetent.io/path: "/eviction-hook"
```

If you have a central service that provides the eviction logic for multiple pods:
```yaml
annotations:
  eviction-webhook.mrincompetent.io/enable: "true"
  eviction-webhook.mrincompetent.io/hostname: "my-pod-protection-service.default.svc.cluster.local"
  eviction-webhook.mrincompetent.io/port: "8080"
  eviction-webhook.mrincompetent.io/scheme: "https"
  eviction-webhook.mrincompetent.io/path: "/eviction-hook"
```

Once the annotations are added, the admission controller will call the specified endpoint before allowing any eviction to take place. If the endpoint responds with a 200 status code, the eviction will be allowed to proceed. If it responds with any other status code, the eviction will be denied.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
