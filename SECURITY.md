# Security policy

## Reporting a vulnerability

Email **DAVANO@davano.net** with `[SECURITY]` in the subject. Please do not open
a public issue for a vulnerability.

Include what you need to make the problem reproducible: the version or image
digest, what you did, what happened, and what you expected. A proof of concept
helps but is not required to report something.

What to expect:

- An acknowledgement within **3 working days**. If you have not heard back in a
  week, assume the mail went astray and send it again — that is a failure on our
  side, not a reason to stay quiet.
- An assessment within **10 working days**, saying whether we agree it is a
  vulnerability and what severity we think it carries. If we disagree with your
  assessment we will say why rather than going silent.
- A fix or a documented mitigation for anything we accept as Critical or High
  within **30 days**, and a public advisory when it ships.

We will credit you in the advisory unless you ask us not to. This project has no
bug bounty.

## Where the product ends

Cupel decides whether a workload is allowed to start. Once it has decided, it is
not consulted again.

That boundary is worth stating because the words nearby invite a stronger claim.
A running model's prompts, its completions, and the tool calls an agent makes on
its behalf are all invisible from where the admission gate stands. **Cupel cannot
prevent a model that is already running from behaving badly**, and nothing in its
configuration changes that. A product that could would have to sit in the
inference path and read what passes through it, which this is not.

Three things follow, and each is a real limit rather than a gap waiting to be
closed:

- **How a model is aligned is not an artifact property.** A model built to refuse
  less is byte-for-byte an ordinary model: correct weights, ordinary config,
  ordinary tokenizer. No inspection can see the difference, here or anywhere
  else. Refusing one is a deployment decision, and the lever for it is
  `requireSignature` against a declared `TrustedPublisher` — an allowlist of who
  may ship models into the cluster, which is blunt on purpose.
- **Agent skills are a different artifact.** Packages pulled from a skill
  marketplace and executed by an agent framework are a real supply-chain problem
  and a close cousin of this one, but they are not model artifacts and Cupel does
  not read them.
- **What is in reach is the load-time path.** A pickle that imports `os.system`,
  a config that hands execution to model-supplied code, a chat template that
  reaches the interpreter — these run before the first token, ahead of any
  guardrail being consulted. That is the part of the problem an artifact scanner
  can actually settle, and it is what Cupel settles.

## When the gate itself is not consulted

The webhook is one component, and a component can be down. What happens then is
a deployment choice, and it is worth stating plainly rather than leaving it to a
comment in a values file.

By default `webhook.failurePolicy` is `Ignore`: if the gate is unreachable or
slow to answer, the API server admits the workload and Cupel is never asked.
That keeps an outage in Cupel from blocking every model deployment in the
cluster, and it means **anyone who can disrupt Cupel can also bypass it**. Set
it to `Fail` where that trade is the wrong way round; the gate then blocks
deployments while it is unavailable, so run more than one replica if you do.

Two related defaults follow the same reasoning and are not configurable:

- The `SecurityException` and promotion webhooks are pinned to `Fail`. An
  exception is a written record that risk was accepted, and one admitted while
  the validator was down is a record nobody checked.
- There is no self-signed certificate fallback. A webhook whose certificate the
  API server cannot verify is skipped silently under `Ignore`, which looks
  exactly like a working gate.

An approval is also a statement about what was examined. When part of an
artifact could not be read, the verdict says so — the admission response carries
a warning naming how much went unread, the decision is recorded, and
`blockUnexamined` on the scan policy refuses such artifacts outright.

## What counts as a vulnerability here

Cupel is a security tool, which makes the boundary worth stating plainly.

**These are vulnerabilities. Please report them.**

- A way to make a scan report `Approved` for an artifact that should not be —
  particularly anything that gets a malicious pickle, an embedded credential or
  a malware detection past the policy engine.
- A way to get past the admission gate: a workload deployed with a model that
  has no verdict, a quarantined verdict, or a verdict belonging to different
  bytes.
- Any path where a scan fails and the result reads as clean rather than as
  failed. Cupel is built to fail closed, and a fail-open path is the most
  serious class of bug this project has.
- Reading findings, model names or any other data outside your role and tenant
  through the console API.
- Anything that lets a scanned artifact execute code in the operator, the API
  server, or outside its own sandboxed scan Job. Scanners process hostile input
  by design; escaping that boundary is a real finding.
- Recording an acceptance without the approver's authenticated identity, or
  altering an audit record without breaking the chain.
- Credential disclosure: a token in a log, a Secret reaching a scan pod, a
  credential in an evidence bundle.

**These are not vulnerabilities, though they may still be bugs worth filing
publicly.**

- A model that is malicious in a way no artifact inspection could observe. Every
  scan states the coverage behind its verdict, so what a given result speaks to
  is visible in the result itself.
- A false positive. Annoying, and we want to hear about it, but it fails closed.
- Findings against the demonstration console when it is run without TLS through
  a port-forward. That configuration is documented as a local convenience and
  warns at startup.
- Anything requiring cluster-admin to exploit. If you already have cluster-admin
  you do not need a vulnerability in Cupel.

## Supported versions

Fixes go to the latest tagged release.

## Verifying what you run

Images are published to `ghcr.io/davano-innovation-lab`. Pin by digest rather
than tag if you care about what you are running:

```bash
docker pull ghcr.io/davano-innovation-lab/cupel-operator@sha256:<digest>
```

Cupel verifies signatures on the models it scans, and its own images are signed
the same way. Signing is keyless, so there is no key to trust — the certificate
names the repository and the workflow that built the image:

```bash
cosign verify \
  --certificate-identity-regexp '^https://github.com/DAVANO-INNOVATION-LAB/cupel/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/davano-innovation-lab/cupel-operator:0.2.4
```
