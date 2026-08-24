# Compliance

Cupel produces evidence. It does not produce compliance.

That distinction is the whole of this page. A control is satisfied by a system,
assessed by a person, inside a documented boundary. A scanner is one input to
that assessment. Any vendor telling you their tool "makes you compliant with
X" is describing a conversation with an authorizing official that has not
happened yet.

What Cupel does is make the evidence for a specific slice — the model artifact
layer — machine-generated, portable, and checkable by someone who does not
trust the party that produced it.

## Why this matters now

**NDAA FY2026 Section 1513** directs the Department of Defense to build an AI
security framework for contractors and fold it into DFARS as an extension of
CMMC. It names data-poisoning defence, adversarial-tampering protection, and
protection of "source code, model weights, and the methods, algorithms, data"
used to build a model.

That moves AI bills of materials and model provenance out of the
recommended-practice column and into the contractual one, for every company in
the Defense Industrial Base. The **DoD AI Cybersecurity Risk Management
Tailoring Guide** (DoD CIO, v2, July 2025) is the operational companion: it
maps MITRE ATLAS threat vectors onto CNSSI 1253 and NIST SP 800-53 controls,
and separates an *infrastructure layer* from a *model layer*.

Cupel works the model layer.

## What Cupel maps to

| Framework | Where |
|---|---|
| **NIST SP 800-53 Rev 5** — the controls an artifact scanner speaks to | [`internal/compliance/nist80053.go`](../internal/compliance/nist80053.go) |
| **NIST AI RMF 1.0** — all 72 subcategories, most marked unobservable | [`internal/compliance/catalog.go`](../internal/compliance/catalog.go) |
| **MITRE ATLAS** (release 2026.07) — technique mapping with the evidence behind each | [`internal/compliance/atlas.go`](../internal/compliance/atlas.go) |

**CNSSI 1253** shares 800-53's control identifiers, so the mapping carries
across. What it adds is the National Security Systems categorization and
overlay — which controls apply at which impact level. That is a system
decision and no tool can make it for you.

### The controls Cupel fits best

- **CM-14 Signed Components** — the closest fit in the catalogue to what the
  admission gate does. `TrustedPublisher` is the organization's list of
  recognised certificates; a policy requiring a signature refuses deployment
  without one, including when the signature covers only part of the artifact.
- **SR-4 Provenance** and **SR-11 Component Authenticity** — Sigstore
  verification, with the signer identity recorded against the bytes.
- **SR-10 Inspection of Systems or Components** — the scan itself, with the
  coverage record treated as part of the result.
- **RA-5 Vulnerability Monitoring and Scanning** — on registration, on
  deployment, and on a schedule, because a verdict describes what was known
  when it ran.
- **SI-7 Software, Firmware, and Information Integrity** — every verdict is
  bound to a digest, and an approval cannot be replayed onto different bytes
  published under the same name.

### The gaps, stated because an assessor will find them

- **SA-11 Developer Testing and Evaluation** — Cupel assesses an artifact it is
  handed. Whether the party that built the model tested it is not observable,
  and third-party models almost never come with an answer.
- **AU-9 Protection of Audit Information** — the audit chain makes tampering
  *evident*, not impossible. Someone who controls the store can rewrite the
  whole chain; only an externally anchored checkpoint closes that.
- **RA-3 Risk Assessment** — a risk score over an artifact's findings is not a
  risk assessment of a system. Likelihood and magnitude of harm depend on what
  the model is used for.
- **Weight-level poisoning and training-data poisoning** — named in §1513, and
  structurally invisible to any static scanner. A backdoored model is
  byte-identical to a clean one. This needs behavioural evaluation, and saying
  otherwise is the claim most likely to fail an assessment.

## The evidence bundle

The artefact an authorizing official can actually use:

```bash
cupel-runner verify-evidence bundle.json
```

```
subject:   fraud-detector/v3
verdict:   Approved (risk 62)
digest:    unmodified
audit:     intact
coverage:  3 of 4 scanners completed

problems:
  - 1 of 4 scanners did not complete ([trivy]); the verdict rests on less
    evidence than was requested

not assessed by this tool:
  - Weight-level model poisoning (AML.T0018.000) ...
```

Four properties are deliberate:

1. **Offline.** Everything needed to check it is inside the file. An assessor
   with no access to your cluster, and frequently no network, can still verify
   it. An evidence package that has to phone home is useless where it is most
   needed.
2. **Tamper-evident.** Editing any field breaks the digest. Editing an audit
   record breaks the chain even if the outer digest is recomputed.
3. **Coverage travels with the verdict.** The bundle records which scanners
   produced the result, so an assessor can see what the verdict rests on
   instead of taking it on trust.
4. **Scope is stated, not implied.** Every bundle names the assessment classes
   it speaks to, so a reader knows what the evidence supports.

Exit codes: `0` intact, `4` does not verify, `1` unreadable.

## For an assessment

Cupel contributes to a body of evidence. Expect to also show:

- The organizational controls in the AI RMF mapping — most of the 72
  subcategories are policy and process, and are marked unobservable for that
  reason.
- Infrastructure-layer controls, which are outside what a model scanner sees.
- Behavioural evaluation, for anything about how the model acts rather than
  what it contains.

If a control is closed here, the mapping says which evidence closed it. If it
is not, the mapping says why. Both are more useful to an assessor than a
percentage.
