# Assay

[![CI](https://github.com/DAVANO-INNOVATION-LAB/assay/actions/workflows/ci.yml/badge.svg)](https://github.com/DAVANO-INNOVATION-LAB/assay/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/DAVANO-INNOVATION-LAB/assay.svg)](https://pkg.go.dev/github.com/DAVANO-INNOVATION-LAB/assay)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**A model with a backdoor in it looks exactly like a model without one.**

Assay is model supply-chain security for Kubernetes. It scans every version a
model registry publishes, records a verdict, and refuses to let an unapproved
model reach a running workload.

It runs on any conformant cluster — vanilla Kubernetes, EKS, GKE, AKS, kind,
k3s, OpenShift — and uses no vendor-specific API objects. The command-line tool
needs no cluster at all: it is a static Linux or macOS binary that scans a model
wherever you have one.

## Assay and Tessera

Two projects, one engine, and the split is deliberate.

[**Tessera**](https://github.com/DAVANO-INNOVATION-LAB/tessera) reads the
artifact. It opens GGUF, safetensors and ONNX, walks what sits beside them, and
emits a bill of materials. It runs anywhere — a laptop, a CI job, one container,
an air-gapped enclave — with no third-party dependencies in its core.

**Assay** runs Tessera at fleet scale and enforces the result. Controllers,
scheduled rescanning, promotion between environments, a tamper-evident decision
log, and an admission webhook. That last one is the thing a command-line tool
cannot do: a CLI can report, but only something inside the cluster can stop a
Pod from starting.

Assay imports Tessera. Tessera does not know Assay exists.

**Use Tessera if** you want to inspect or document a model.
**Add Assay if** you need the answer enforced across a cluster.

## Install

The CLI is a single static binary and needs no cluster:

```bash
go install github.com/DAVANO-INNOVATION-LAB/assay/cmd/assay@latest
```

Prebuilt binaries for Linux and macOS, amd64 and arm64, are on the
[releases page](https://github.com/DAVANO-INNOVATION-LAB/assay/releases).

The operator installs from the chart. The one setting that depends on your
cluster is how the admission webhook gets its serving certificate:

```bash
# Default: cert-manager issues and rotates it. Works on any cluster.
helm install assay deploy/helm/assay -n assay-system --create-namespace

# OpenShift: the service CA operator does it, with no extra component
helm install assay deploy/helm/assay -n assay-system --create-namespace \
  --set webhook.certMode=openshift

# Or bring your own Secret and CA bundle
--set webhook.certMode=external --set webhook.caBundle=...
```

There is no self-signed fallback on purpose. A webhook whose certificate cannot
be verified is silently skipped, which looks exactly like a working gate.

## Use

Scan a model from anywhere:

```bash
assay inspect ./model-dir
assay inspect hf://openai-community/gpt2
assay inspect s3://bucket/models/fraud-detect
```

```
  [Low     ] TESS-PICKLE-003  Pickle-based weights execute code on load
             at pytorch_model.bin
             this is inherent to the format, not a defect in this model —
             prefer safetensors, which cannot execute anything

  coverage: 25 read in full, 1 header-only, 0 not read
  verdict:  Approved (risk score 0/100)
```

Note what that says. gpt2's pickle weights *can* execute code, and Assay reports
it — at Low, and still approves the model, because that is true of every pickle
ever shipped and is not a defect in this one. A scanner that raises an alarm on
the ordinary case is a scanner people switch off. It also reports that one file
was read header-only, because what was *not* examined is part of a verdict.

## In a cluster

Point Assay at a model registry and it does the rest:

```yaml
apiVersion: security.davano.io/v1alpha1
kind: ModelRegistryConnector
metadata:
  name: model-registry
  namespace: assay-system
spec:
  endpoint: https://model-registry.example.com
  pollInterval: 5m
```

Every version it has not seen opens a scan. The verdict lands on a
`ModelSecurityReport`, is written back to the registry, and the admission
webhook reads it when a workload asks to run that model.

Promotion is explicit. A version approved for `dev` is not approved for `prod`
until a `PromotionRequest` says so, and the gate refuses a workload that
declares an environment the version was never promoted to.

![The Assay console](docs/images/console-scan.png)

## What it covers

| | |
|---|---|
| Formats | GGUF, safetensors, ONNX, pickle, PyTorch, Keras, SavedModel, NumPy, archives |
| Sources | Hugging Face, S3 and compatible, OCI and ModelCar, PVC, MLflow, Kubeflow and Red Hat OpenShift AI model registries |
| Scanners | model inspection, plus ClamAV, Trivy, Grype, Syft and TruffleHog as Jobs |
| Frameworks | NIST AI RMF 1.0, NIST SP 800-53r5, MITRE ATLAS 2026.07 |
| Signing | Sigstore verification against declared trusted publishers |

Its limits are documented rather than implied. A model poisoned in its *weights*
is byte-identical to a clean one, and no static scanner can see it — so Assay
says so, in [SECURITY.md](SECURITY.md) and in the
[MITRE ATLAS coverage map](internal/compliance/atlas.go), instead of letting
silence imply coverage.

## Documentation

| | |
|---|---|
| [Console](docs/console.md) | interface, OIDC, and authorization |
| [Compliance](docs/compliance.md) | framework reporting |
| [Security](SECURITY.md) | what a static scan can and cannot see |
| [Tessera](https://github.com/DAVANO-INNOVATION-LAB/tessera) | the engine underneath |

## Licence

Apache-2.0.
