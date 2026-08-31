#!/usr/bin/env bash
# Install Cupel into a real cluster, prove the gate works, upgrade it, roll it
# back, and prove the gate still works.
#
# Rendering a chart proves the templates produce YAML. It does not prove the
# CRDs apply, that the operator starts, that the webhook is reachable, or that
# an upgrade over an existing install survives a CRD schema change — and those
# are the failures that reach a user, because they happen on their cluster and
# not on ours.
#
# Usage: hack/cluster-conformance.sh [k8s-node-image]
set -euo pipefail

NODE_IMAGE="${1:-kindest/node:v1.31.0}"
CLUSTER="cupel-conformance"
NS="cupel-system"
CHART="deploy/helm/cupel"
IMAGE="cupel:conformance"
CERT_MANAGER_VERSION="v1.16.2"

log() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
cleanup() { kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

log "kind cluster on ${NODE_IMAGE}"
kind create cluster --name "$CLUSTER" --image "$NODE_IMAGE" --wait 120s

log "cert-manager ${CERT_MANAGER_VERSION}"
# The chart's default cert mode. Installing it is part of proving the default
# path works on a cluster that is not OpenShift.
kubectl apply -f "https://github.com/cert-manager/cert-manager/releases/download/${CERT_MANAGER_VERSION}/cert-manager.yaml"
kubectl -n cert-manager wait --for=condition=Available --timeout=300s \
  deploy/cert-manager deploy/cert-manager-webhook deploy/cert-manager-cainjector

log "build and load the operator image"
docker build -t "$IMAGE" .
kind load docker-image "$IMAGE" --name "$CLUSTER"

install_chart() {
  local action="$1"
  helm "$action" cupel "$CHART" \
    --namespace "$NS" --create-namespace \
    --set image.repository=cupel --set image.tag=conformance \
    --set image.pullPolicy=Never \
    --wait --timeout 5m
}

log "install"
install_chart install

wait_ready() {
  kubectl -n "$NS" rollout status deploy/cupel --timeout=180s
  # An endpoint-less webhook Service is admitted under failurePolicy Ignore and
  # looks exactly like a working gate, so wait for a real endpoint rather than
  # for the Deployment alone.
  for _ in $(seq 1 60); do
    if [ -n "$(kubectl -n "$NS" get endpoints cupel-webhook \
        -o jsonpath='{.subsets[*].addresses[*].ip}' 2>/dev/null)" ]; then
      return 0
    fi
    sleep 2
  done
  echo "webhook service never got an endpoint" >&2
  kubectl -n "$NS" get pods,endpoints >&2
  return 1
}
wait_ready

log "CRDs are established"
for crd in $(kubectl get crd -o name | grep security.davano.io); do
  kubectl wait --for=condition=Established --timeout=60s "$crd"
done

# The gate only acts on namespaces that opt in.
kubectl create namespace models --dry-run=client -o yaml | kubectl apply -f -
kubectl label namespace models security.davano.io/enforce=true --overwrite

# The gate looks reports up by a derived name, so plant one the gate will
# actually find. A report under any other name is no report at all, and the
# gate would admit — passing this script for the wrong reason.
REPORT_NAME="$(go run ./hack/reportname conformance 1)"

gate_probe() {
  # A quarantined model must be refused. This is the whole product in one
  # assertion: if it passes, the CRDs applied, the operator is running, the
  # webhook is reachable and its certificate verified.
  local phase="$1"
  kubectl -n models apply -f - >/dev/null <<YAML
apiVersion: security.davano.io/v1alpha1
kind: ModelSecurityReport
metadata:
  name: ${REPORT_NAME}
spec:
  modelName: conformance
  modelVersion: "1"
YAML
  kubectl -n models patch modelsecurityreport "$REPORT_NAME" \
    --subresource=status --type=merge \
    -p '{"status":{"verdict":"Quarantined","riskScore":100,"malware":"Detected"}}' >/dev/null

  if kubectl -n models apply --dry-run=server -f - >/dev/null 2>&1 <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: serving
  annotations:
    security.davano.io/model: conformance
    security.davano.io/model-version: "1"
spec:
  replicas: 1
  selector: { matchLabels: { app: serving } }
  template:
    metadata:
      labels: { app: serving }
    spec:
      containers:
        - name: serve
          image: registry.k8s.io/pause:3.10
YAML
  then
    echo "FAIL (${phase}): a quarantined model was admitted" >&2
    return 1
  fi
  echo "ok (${phase}): quarantined model refused"

  # The converse, so the probe cannot pass by refusing everything — a gate that
  # denies unconditionally would satisfy the assertion above.
  kubectl -n models patch modelsecurityreport "$REPORT_NAME" \
    --subresource=status --type=merge \
    -p '{"status":{"verdict":"Approved","riskScore":0}}' >/dev/null
  if ! kubectl -n models apply --dry-run=server -f - >/dev/null 2>&1 <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: serving
  annotations:
    security.davano.io/model: conformance
    security.davano.io/model-version: "1"
spec:
  replicas: 1
  selector: { matchLabels: { app: serving } }
  template:
    metadata:
      labels: { app: serving }
    spec:
      containers:
        - name: serve
          image: registry.k8s.io/pause:3.10
YAML
  then
    echo "FAIL (${phase}): an approved model was refused" >&2
    return 1
  fi
  echo "ok (${phase}): approved model admitted"
}

log "gate works on a fresh install"
gate_probe "install"

# The upgrade path is where a CRD schema change bites: helm upgrade applies the
# new CRDs over resources created under the old ones.
log "upgrade over the existing release"
install_chart upgrade
wait_ready
gate_probe "upgrade"

log "rollback"
helm rollback cupel 1 --namespace "$NS" --wait --timeout 5m
wait_ready
gate_probe "rollback"

log "PASS on ${NODE_IMAGE}"
