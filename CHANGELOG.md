# Changelog

## v0.2.4

Documentation and positioning. The README, SECURITY.md, the compliance guide and
the console now describe what Cupel is scoped to do and what each result rests
on, in place of component-by-component maturity notes and a phased plan.

The scanner catalog lists only scanners that ship. The status tables name
Sigstore verification against a `TrustedPublisher`, the AI bill of materials,
the promotion workflow and the broadened admission gate.

No behaviour changes. Every scan still records the coverage behind its verdict,
every evidence bundle still names the assessment classes it speaks to, and the
ATLAS mapping still ties each result to the technique it evidences — that is the
product telling an operator what a verdict rests on, and it is load-bearing.

## v0.2.3

**Pinned scanner versions moved to current upstream releases.** The pins had
drifted a long way — syft was 33 minor versions behind, grype 30, trufflehog 9,
trivy 2. A scanner image vendors a third-party binary and bakes its database,
so a pin nothing touches ships someone else's old build indefinitely; nothing
renews it on its own.

| tool | was | now |
|---|---|---|
| syft | 1.18.1 | 1.51.0 |
| grype | 0.87.0 | 0.117.0 |
| trufflehog | 3.88.2 | 3.97.0 |
| trivy | 0.72.0 | 0.74.0 |

Verified rather than assumed: all four rebuild, and the air-gapped smoke test
still proves each detects what it claims to — the EICAR file, the planted AWS
key, CVEs from the baked database, and an SPDX document with the pinned
dependencies catalogued. That check is why bumping a scanner is done carefully:
one that silently stopped finding things is worse than one that is out of date.

The checked-in manifests, the Helm chart and the scanner catalog all pin the
release tag, so a manifest applied from this tag deploys this release. Go
dependencies and the GitHub Actions are on current versions.


## v0.2.0

Six features across the artifact, the gate and the release pipeline.

### The model itself is described

Cupel imports [Tessera](https://github.com/DAVANO-INNOVATION-LAB/tessera) and
produces a **CycloneDX 1.6 ML-BOM and an SPDX 3.0.1 document** from the model's
own binary headers — architecture, measured parameter count, precision, tensor
shapes, licence, declared lineage, and per-file SHA-256, SHA-384 and SHA-512.
Pinned to Tessera v0.3.0, so the documents also carry the **BSI TR-03183-2**
component properties.

**Drift** comes with it: a config advertising a precision the tensors do not
carry is the artifact being something other than what it says it is.
`blockModelDrift` gates on it, off by default, because a quantized re-upload
carrying its original config is the common case.

`requireAIBOM` is satisfied by a document, not by a scanner having run — the
two are distinguished so the rule means what it says.

### Keras and TensorFlow

`.keras`, `.h5` and `.pb` are inspected for their load-time execution paths:
**Lambda layers**, which carry a marshalled Python code object; **TFSMLayer**,
which loads an external SavedModel from a path in the config; configs naming
arbitrary modules to import; and SavedModel graph operations that reach outside
the graph. Detection prefers content over extension in both directions.

### The gate reads what a workload is configured to do

Serving intent is read from images, environment variables, `--model` flags and
volume mounts across Deployments, StatefulSets, DaemonSets, Jobs, CronJobs and
Pods — not only from annotations. A scheme-qualified storage URI resolves to
the real verdict; anything less specific is reported rather than guessed at,
because a verdict about the wrong model is worse than none.

### Admission decisions are recorded

Every denial, and every admission that rested on something other than a clean
verdict, is sealed into the tamper-evident chain with the authenticated
username. Chain-write failures increment
`cupel_audit_write_failures_total` and never change the decision.

### The promotion workflow

`PromotionRequest` carries a signed human decision per environment. The
controller establishes what is permissible — a model whose verdict is not
Approved cannot be promoted, and that is `Blocked` rather than `Rejected`,
because no person decided it. A person decides whether it happens. The verdict
is re-read at the moment the decision is acted on, so an approval cannot carry
over to a verdict it was not given against.

Both admission signers ship in the Helm chart.

### Signed images

Keyless cosign signing, by digest, with `--recursive` so each platform's child
manifest is covered. The release job verifies its own signatures before
finishing.

```
cosign verify \
  --certificate-identity-regexp '^https://github.com/DAVANO-INNOVATION-LAB/cupel/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/davano-innovation-lab/cupel-operator:0.2.4
```

A **Docker Hub mirror** at `docker.io/davanolab` publishes from the same job
when credentials are configured. It copies the manifest rather than rebuilding,
so both registries serve identical digests and one signature covers both.

### Compatibility

`v1alpha1` gains fields with no breaking changes. `PromotionRequestSpec` adds
`decision`, `decisionReason`, `decidedBy`, `decidedByGroups` and `decidedAt`;
`ScannerResult` adds `drift` and `produced`; `ModelSecurityReportStatus` adds
`aibomRef`; `PolicyRules` adds `requireAIBOM` and `blockModelDrift`.

The `cupel-promotion-signer` webhook has `failurePolicy: Fail`, so a
`PromotionRequest` is only accepted when its approver can be established.

## v0.1.0

Initial public release.
