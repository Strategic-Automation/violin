# Kubernetes Configuration and Workload-Boundary Review

Use only operator-supplied manifests, version/configuration evidence, and
authorized observations. A hostname, discovered kubeconfig, cluster banner, or
manifest does not authorize cluster activity. Name the cluster/context,
namespace, service account, workload and resource before interpreting a rule.

## Review workflow

Trace a synthetic service account -> Role/ClusterRole -> binding -> workload ->
resource/action. Review verbs and resource names, namespace scope, pod security
settings, host namespaces/devices, privileged containers, secret mounts,
admission controls, network policy and exposed services. Record Kubernetes
version, relevant feature gates, policy/controller presence, and whether a
configuration is merely declared or observed to be enforced.

Example: a namespaced Role grants `get` on ConfigMaps in `demo`; a binding
connects it to service account `reader`, used by deployment `frontend`. Do not
infer that the workload can read a Secret or act in another namespace. Confirm
the exact resource and effect only with an explicitly authorized synthetic
fixture and supported runtime. Missing controllers or cluster state remain
limitations.

## Evidence

Store supplied files and provenance under `$ENG_DIR/evidence/recon/`. For
permitted live checks, use current registered guarded execution and a disposable
test resource; capture principal, context, namespace, request, and returned
content in evidence sealed by its receipt.

## Stop Conditions

- Stop if the authorized context, namespace, or resource is unclear.
- Stop before reading non-test Secrets, entering a pod, or changing cluster
  state.
- Report absent runtime controls as blocked or inconclusive.

## Blocked Actions

No cluster mutation, `exec` into pods, privilege escalation, secret extraction,
new `kubectl` installation, or inferred cluster-wide authorization.

## References

- [Kubernetes RBAC authorization](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
