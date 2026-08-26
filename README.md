# Cupel

[![CI](https://github.com/DAVANO-INNOVATION-LAB/cupel/actions/workflows/ci.yml/badge.svg)](https://github.com/DAVANO-INNOVATION-LAB/cupel/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/DAVANO-INNOVATION-LAB/cupel.svg)](https://pkg.go.dev/github.com/DAVANO-INNOVATION-LAB/cupel)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**A model with a backdoor in it looks exactly like a model without one.**

Cupel is model supply-chain security for Kubernetes. It scans every version a
model registry publishes, records a verdict, and refuses to let an unapproved
model reach a running workload.

It runs on any conformant cluster — vanilla Kubernetes, EKS, GKE, AKS, kind,
k3s, OpenShift — and uses no vendor-specific API objects. The command-line tool
needs no cluster at all: it is a static Linux or macOS binary that scans a model
wherever you have one.

## Cupel and Tessera

Two projects, one engine, and the split is deliberate.

[**Tessera**](https://github.com/DAVANO-INNOVATION-LAB/tessera) reads the
artifact. It opens GGUF, safetensors and ONNX, walks what sits beside them, and
emits a bill of materials. It runs anywhere — a laptop, a CI job, one container,
an air-gapped enclave — with no third-party dependencies in its core.

**Cupel** runs Tessera at fleet scale and enforces the result. Controllers,
scheduled rescanning, promotion between environments, a tamper-evident decision
log, and an admission webhook. That last one is the thing a command-line tool
cannot do: a CLI can report, but only something inside the cluster can stop a
Pod from starting.

Cupel imports Tessera. Tessera does not know Cupel exists.

**Use Tessera if** you want to inspect or document a model.
**Add Cupel if** you need the answer enforced across a cluster.

## Install

The CLI is a single static binary and needs no cluster:

```bash
go install github.com/DAVANO-INNOVATION-LAB/cupel/cmd/cupel@latest
```

Prebuilt binaries for Linux and macOS, amd64 and arm64, are on the
[releases page](https://github.com/DAVANO-INNOVATION-LAB/cupel/releases).

The operator installs from the chart. The one setting that depends on your
cluster is how the admission webhook gets its serving certificate:

```bash
# Default: cert-manager issues and rotates it. Works on any cluster.
helm install cupel deploy/helm/cupel -n cupel-system --create-namespace

# OpenShift: the service CA operator does it, with no extra component
helm install cupel deploy/helm/cupel -n cupel-system --create-namespace \
  --set webhook.certMode=openshift

# Or bring your own Secret and CA bundle
--set webhook.certMode=external --set webhook.caBundle=...
```

There is no self-signed fallback on purpose. A webhook whose certificate cannot
be verified is silently skipped, which looks exactly like a working gate.

## Use

Scan a model from anywhere:

```bash
cupel inspect ./model-dir
cupel inspect hf://openai-community/gpt2
cupel inspect s3://bucket/models/fraud-detect
```

```
  [Low     ] TESS-PICKLE-003  Pickle-based weights execute code on load
             at pytorch_model.bin
             this is inherent to the format, not a defect in this model —
             prefer safetensors, which cannot execute anything

  coverage: 25 read in full, 1 header-only, 0 not read
  verdict:  Approved (risk score 0/100)
```

An archived decision log verifies from the files alone, with no cluster and no
credentials — which is the state an auditor is usually in:

```bash
cupel audit verify ./audit-archive --checkpoint checkpoint.json
```

Note what that says. gpt2's pickle weights *can* execute code, and Cupel reports
it — at Low, and still approves the model, because that is true of every pickle
ever shipped and is not a defect in this one. A scanner that raises an alarm on
the ordinary case is a scanner people switch off. It also reports that one file
was read header-only, because what was *not* examined is part of a verdict.

## In a cluster

Point Cupel at a model registry and it does the rest:

```yaml
apiVersion: security.davano.io/v1alpha1
kind: ModelRegistryConnector
metadata:
  name: model-registry
  namespace: cupel-system
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

A policy can refuse an artifact the scanner could not fully read. Without
`blockUnexamined`, a file that was recognised and failed to parse produces a
report identical to one that was read and found clean — no findings either way:

```yaml
rules:
  blockUnexamined: true
```

Off by default, because it refuses artifacts that are admitted today.

An approval can be given a shelf life. A model version is a mutable pointer in
most registries, so the bytes behind an approved name can change after the
approval was given:

```bash
--set gate.maxReportAgeDays=180   # or 365
```

Off by default, because any limit refuses workloads that are admitted today. A
stale approval is refused with a message saying to rescan; a stale denial stays
a denial.

Cupel is meant to be left running. Finished scans age out on a retention
window, the decision log can be archived out of the cluster once it grows past a
threshold, and the chain's length is published as a metric — so what it stores
tracks recent activity rather than uptime. Archived records stay part of the same
verifiable chain: the checkpoint records where they went, and `cupel audit
verify` checks them against it.

![The Cupel console](docs/images/console-scan.png)

## What it covers

| | |
|---|---|
| Formats | GGUF, safetensors, ONNX, pickle, PyTorch, Keras, SavedModel, NumPy, archives |
| Sources | Hugging Face, S3 and compatible, OCI and ModelCar, PVC, MLflow, Kubeflow and Red Hat OpenShift AI model registries |
| Scanners | model inspection, plus ClamAV, Trivy, Grype, Syft and TruffleHog as Jobs |
| Frameworks | NIST AI RMF 1.0, NIST SP 800-53r5, MITRE ATLAS 2026.07 |
| Signing | Sigstore verification against declared trusted publishers |

Its limits are documented rather than implied. A model poisoned in its *weights*
is byte-identical to a clean one, and no static scanner can see it — so Cupel
says so, in [SECURITY.md](SECURITY.md) and in the
[MITRE ATLAS coverage map](internal/compliance/atlas.go), instead of letting
silence imply coverage.

The same goes for where it stops. Cupel decides whether a workload starts; it
sees no prompt, no completion and no tool call, so it cannot prevent a running
model from behaving badly. What it settles is the load-time path — the code that
runs before the first token. [Where the product ends](SECURITY.md#where-the-product-ends)
sets out the boundary.

## Documentation

| | |
|---|---|
| [Console](docs/console.md) | interface, OIDC, and authorization |
| [Compliance](docs/compliance.md) | framework reporting |
| [Security](SECURITY.md) | what a static scan can and cannot see |
| [Tessera](https://github.com/DAVANO-INNOVATION-LAB/tessera) | the engine underneath |

## Licence

Apache-2.0.
