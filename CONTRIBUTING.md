# Contributing

## Before anything else

If you have found a way to make Cupel report something as safe when it is not,
that is a security report, not an issue. See [SECURITY.md](SECURITY.md).

## Getting a working checkout

```bash
git clone https://github.com/DAVANO-INNOVATION-LAB/cupel
cd cupel
make test          # unit suite, race-enabled
make lint          # go vet plus golangci-lint
make build         # binaries into bin/
```

Go 1.25 or later. `make test` needs nothing but Go. Anything touching a cluster
uses `kind`, and `make kind-up` will build you one.

To exercise the whole pipeline end to end, including a model registry and live
scans:

```bash
make kind-up            # cluster, CRDs, operator
make demo               # MLflow, seeded models, a scan of each
```

## What good looks like here

**Fail closed, and prove it.** The most serious defect class in this project is
a path where something goes wrong and the result reads as clean. Two real
examples, both found after they shipped: a scanner whose name was not in the
catalog had its findings silently dropped, so twelve Criticals produced
`Approved risk 0`; and a file the inspector could not parse was reported at
`Low`, which the policy engine approves — the exact evasion MITRE ATLAS names as
`AML.T0076`. If your change adds a branch that can end in "no findings", make
sure the difference between *found nothing* and *did not look* survives.

**Tests state what breaks, not what runs.** A test named
`TestUnreadableExecutableFormatIsHighSeverity` with a failure message explaining
why an approved-severity finding on an unparseable pickle is dangerous is worth
more than three tests named `TestSeverity1`. Where a test guards against a
regression that actually happened, say so in a comment — several tests here are
written specifically to fail against the code that shipped the bug.

**Comments explain the decision, not the syntax.** `// increment i` is noise.
`// Nothing finished yet: either the first scan is still running, or a previous
rescan is. Either way there is no age to measure.` is why the next person does
not delete the nil check.

**Don't claim coverage you do not have.** The ATLAS mapping in
`internal/compliance/atlas.go` deliberately lists techniques Cupel cannot detect,
with the reason. Adding a technique to the detected list requires the detection
to exist. There are tests that fail if weight-level poisoning is ever marked as
covered.

## Pull requests

- One concern per PR. A bug fix and a refactor in the same diff is two PRs.
- `make test lint` must pass. CI runs the same commands, plus a race-enabled
  suite, a CLI end-to-end check and a live MLflow scan.
- Commit messages: a short subject in the imperative, then prose explaining why
  the change was needed and what you considered. If you fixed a bug, say how it
  manifested — future readers are usually trying to work out whether their
  symptom is the same one.
- New CRD fields need `make manifests generate` run and the result committed.

## Adding a scanner

Scanners are containers that read a staged artifact and write findings to a
file. See `internal/scanners/catalog.go` for the definition shape and
`scanners/` for the images.

A scanner needs:

1. An entry in the catalog with its category and result format.
2. A parser in `internal/results/` if it does not emit Cupel's native JSON.
3. An image under `scanners/`, with its vulnerability database baked in — scan
   Jobs run with networking disabled, and a scanner that needs to phone home
   will fail on an air-gapped cluster.
4. A smoke test in `scanners/smoke-test.sh` proving it finds a planted artifact.

Add the catalog entry in the same change that publishes the image, so a policy
can never name a scanner that cannot be pulled.

## Things we will probably push back on

- Vendoring a large dependency to use one function from it.
- Anything that makes a scan pod hold cluster credentials. Only the publish step
  gets a token, and it gets it through a projected volume rather than an
  automounted service-account token.
- Loosening a default in the permissive direction. Defaults here fail closed on
  purpose, including the ones that make the first run less convenient.
- New network calls at scan time. The scan sandbox has no networking and that is
  a feature.
