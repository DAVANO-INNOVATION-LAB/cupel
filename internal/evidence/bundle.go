// Package evidence produces a portable, verifiable record of why a model was
// allowed or refused.
//
// The problem it addresses is procedural rather than technical. Authorizing an
// AI system today takes months, and much of that is an authorizing official
// re-establishing facts somebody already established. A scan result that lives
// only in a cluster cannot be handed to them; a PDF of a dashboard is not
// evidence, because nothing about it can be checked.
//
// A bundle is the middle thing: a single file holding the verdicts, the
// findings behind them, who accepted which risks, the control mappings, and
// the audit chain — with enough digests inside it that a reader who trusts none
// of it can verify the parts that matter. It is deliberately offline. An
// evidence package that has to phone home is useless in the environments that
// need it most.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/audit"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/compliance"
)

// BundleVersion is the schema version of the bundle format.
const BundleVersion = "cupel-evidence/v1"

// Bundle is a self-contained record for one model version.
type Bundle struct {
	Schema string `json:"schema"`
	// GeneratedAt is when the bundle was assembled.
	GeneratedAt time.Time `json:"generatedAt"`
	// Producer identifies the Cupel build that made it.
	Producer string `json:"producer"`

	Subject Subject `json:"subject"`
	Verdict Verdict `json:"verdict"`

	// Findings behind the verdict.
	Findings []securityv1alpha1.Finding `json:"findings,omitempty"`
	// Scanners that ran, and what each concluded.
	Scanners []ScannerRun `json:"scanners,omitempty"`
	// Acceptances are risks a human took responsibility for.
	Acceptances []Acceptance `json:"acceptances,omitempty"`
	// Coverage records what was NOT examined. An evidence package that omits
	// this is claiming completeness it does not have.
	Coverage Coverage `json:"coverage"`
	// Controls maps the evidence onto governance frameworks.
	Controls ControlMapping `json:"controls"`
	// Audit is the tamper-evident chain covering this subject.
	Audit AuditSection `json:"audit"`

	// Digest commits to every field above. It is computed over a canonical
	// rendering, so a bundle that has been edited will not match.
	Digest string `json:"digest"`
}

// Subject is what the bundle is about.
type Subject struct {
	Model   string `json:"model"`
	Version string `json:"version"`
	// ArtifactURI is where the bytes came from.
	ArtifactURI string `json:"artifactUri,omitempty"`
	// ArtifactDigest binds this record to specific bytes. Without it the
	// bundle attests to a name, and names get reused.
	ArtifactDigest string `json:"artifactDigest,omitempty"`
	Namespace      string `json:"namespace,omitempty"`
}

// Verdict is the decision and its basis.
type Verdict struct {
	Decision  string    `json:"decision"`
	RiskScore int32     `json:"riskScore"`
	Policy    string    `json:"policy,omitempty"`
	ScannedAt time.Time `json:"scannedAt"`
	// Trigger records why the scan ran, which changes what the verdict means.
	Trigger     string `json:"trigger,omitempty"`
	TriggeredBy string `json:"triggeredBy,omitempty"`
}

// ScannerRun records one scanner's contribution.
type ScannerRun struct {
	Name     string `json:"name"`
	Category string `json:"category,omitempty"`
	// Completed distinguishes "ran and found nothing" from "did not run".
	// Collapsing those is how a partial scan comes to look like a clean one.
	Completed bool   `json:"completed"`
	Findings  int    `json:"findings"`
	Message   string `json:"message,omitempty"`
}

// Acceptance is a risk somebody took responsibility for.
type Acceptance struct {
	FindingIDs []string   `json:"findingIds,omitempty"`
	Rules      []string   `json:"rules,omitempty"`
	Reason     string     `json:"reason"`
	ApprovedBy string     `json:"approvedBy"`
	ApprovedAt time.Time  `json:"approvedAt"`
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
	// Signed records whether the identity was established by the admission
	// webhook or merely asserted. An unsigned acceptance is still a record,
	// but it is not attribution, and the difference has to survive into the
	// evidence rather than being smoothed over.
	Signed bool `json:"signed"`
	// ScannedDigest ties the acceptance to the bytes that were reviewed.
	ScannedDigest string `json:"scannedDigest,omitempty"`
}

// Coverage states the limits of the assessment.
type Coverage struct {
	// ScannersRequested and ScannersCompleted differing means the verdict
	// rests on less than it was meant to.
	ScannersRequested int `json:"scannersRequested"`
	ScannersCompleted int `json:"scannersCompleted"`
	// Incomplete lists scanners that did not produce a result.
	Incomplete []string `json:"incomplete,omitempty"`
	// Gaps are explicit statements of what was not examined.
	Gaps []string `json:"gaps,omitempty"`
	// OutOfScope names threat classes this tool structurally cannot assess,
	// so an authorizing official does not read silence as absence.
	OutOfScope []string `json:"outOfScope"`
}

// ControlMapping ties evidence to frameworks.
type ControlMapping struct {
	// ATLASVersion the technique mapping was built against.
	ATLASVersion string `json:"atlasVersion"`
	// ATLAS is the technique coverage summary.
	ATLAS compliance.ATLASCoverageSummary `json:"atlas"`
	// TechniquesEvidenced are the ATLAS techniques this scan speaks to.
	TechniquesEvidenced []string `json:"techniquesEvidenced,omitempty"`
	// Frameworks lists governance frameworks with a compliance report.
	Frameworks []string `json:"frameworks,omitempty"`
	// AttestationRequired counts controls that no scan can close, which need
	// a named human attestation instead.
	AttestationRequired int `json:"attestationRequired"`
}

// AuditSection carries the tamper-evident chain.
type AuditSection struct {
	// Records concerning this subject.
	Records []audit.Record `json:"records,omitempty"`
	// Checkpoint is the head of the full chain at bundle time. Anchoring this
	// externally is what makes truncation detectable later.
	Checkpoint *audit.Checkpoint `json:"checkpoint,omitempty"`
	// ChainValid is the verification result at bundle time.
	//
	// An empty chain verifies vacuously, so this being true says nothing on
	// its own about whether a trail exists. Present distinguishes the two.
	ChainValid bool `json:"chainValid"`
	// Present reports whether there is an audit trail for this subject at all.
	// Without it, "audit: intact" over zero records reads as an assurance
	// rather than as an absence, which is the misreading a reader of an
	// evidence bundle is least able to check.
	Present bool `json:"present"`
	// ChainProblems records why, when it is not.
	ChainProblems []string `json:"chainProblems,omitempty"`
}

// outOfScopeClasses are the threat classes an artifact scanner cannot assess.
//
// Stated in every bundle on purpose. An authorizing official reading a clean
// report will otherwise reasonably assume these were covered.
var outOfScopeClasses = []string{
	"Weight-level model poisoning (AML.T0018.000): a backdoored model is " +
		"byte-indistinguishable from a clean one and requires behavioural evaluation.",
	"Training data poisoning (AML.T0020): requires visibility into the training data.",
	"Runtime evasion and adversarial inputs (AML.T0043, AML.T0051): require " +
		"monitoring at the inference boundary.",
	"Supply chain rug pull and reputation inflation (AML.T0109, AML.T0111): " +
		"require registry history over time, not a point-in-time scan.",
	"Model behaviour, accuracy, fairness and bias: not properties of an artifact's bytes.",
}

// Build assembles a bundle.
func Build(in Input) (*Bundle, error) {
	b := &Bundle{
		Schema:      BundleVersion,
		GeneratedAt: in.Now.UTC().Truncate(time.Second),
		Producer:    in.Producer,
		Subject:     in.Subject,
		Verdict:     in.Verdict,
		Findings:    in.Findings,
		Scanners:    in.Scanners,
		Acceptances: in.Acceptances,
	}
	if b.GeneratedAt.IsZero() {
		b.GeneratedAt = time.Now().UTC().Truncate(time.Second)
	}

	b.Coverage = buildCoverage(in)
	b.Controls = buildControls(in)
	b.Audit = AuditSection{
		Records:    in.AuditRecords,
		Checkpoint: in.AuditCheckpoint,
	}
	verification := audit.Verify(in.AuditRecords, nil)
	b.Audit.ChainValid = verification.Valid
	b.Audit.ChainProblems = verification.Problems
	b.Audit.Present = len(in.AuditRecords) > 0

	digest, err := b.computeDigest()
	if err != nil {
		return nil, err
	}
	b.Digest = digest
	return b, nil
}

// Input is what Build needs.
type Input struct {
	Now             time.Time
	Producer        string
	Subject         Subject
	Verdict         Verdict
	Findings        []securityv1alpha1.Finding
	Scanners        []ScannerRun
	Acceptances     []Acceptance
	Gaps            []string
	Frameworks      []string
	AttestationOpen int
	AuditRecords    []audit.Record
	AuditCheckpoint *audit.Checkpoint
}

func buildCoverage(in Input) Coverage {
	c := Coverage{
		ScannersRequested: len(in.Scanners),
		Gaps:              in.Gaps,
		OutOfScope:        outOfScopeClasses,
	}
	for _, s := range in.Scanners {
		if s.Completed {
			c.ScannersCompleted++
		} else {
			c.Incomplete = append(c.Incomplete, s.Name)
		}
	}
	sort.Strings(c.Incomplete)
	return c
}

func buildControls(in Input) ControlMapping {
	m := ControlMapping{
		ATLASVersion:        compliance.ATLASVersion,
		ATLAS:               compliance.SummarizeATLASCoverage(),
		Frameworks:          in.Frameworks,
		AttestationRequired: in.AttestationOpen,
	}

	// Only claim techniques the scanners that actually completed speak to.
	// Listing a technique because a scanner was requested would be claiming
	// evidence from a scan that did not run.
	ran := map[string]bool{}
	for _, s := range in.Scanners {
		if s.Completed {
			ran[s.Name] = true
		}
	}
	seen := map[string]bool{}
	for _, tech := range compliance.ATLASTechniques() {
		if tech.Coverage == compliance.CoverageOutOfScope {
			continue
		}
		for _, evidence := range tech.Findings {
			if ran[evidence] && !seen[tech.ID] {
				seen[tech.ID] = true
				m.TechniquesEvidenced = append(m.TechniquesEvidenced, tech.ID)
			}
		}
	}
	sort.Strings(m.TechniquesEvidenced)
	return m
}

// computeDigest hashes the bundle with the digest field cleared, so the value
// commits to everything else and a reader can recompute it.
func (b *Bundle) computeDigest() (string, error) {
	clone := *b
	clone.Digest = ""
	encoded, err := json.Marshal(&clone)
	if err != nil {
		return "", fmt.Errorf("encode bundle for digest: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Verify recomputes a bundle's digest and rechecks its audit chain.
//
// This is the whole point of the format: somebody who trusts nothing about
// where the file came from can still establish that it has not been edited
// since it was produced, and that its audit records are internally consistent.
func Verify(b *Bundle) (Verification, error) {
	v := Verification{}

	want, err := b.computeDigest()
	if err != nil {
		return v, err
	}
	v.DigestMatches = want == b.Digest
	if !v.DigestMatches {
		v.Problems = append(v.Problems, fmt.Sprintf(
			"the bundle has been modified since it was produced: contents hash to %s "+
				"but it carries %s", short(want), short(b.Digest)))
	}

	chain := audit.Verify(b.Audit.Records, b.Audit.Checkpoint)
	v.ChainValid = chain.Valid
	v.Problems = append(v.Problems, chain.Problems...)

	// An empty chain is internally consistent, so reporting only "intact"
	// would let a bundle with no audit trail read like one with a clean trail.
	// The bundle is still authentic; the reader just has less than they think.
	if len(b.Audit.Records) == 0 {
		v.Problems = append(v.Problems,
			"there is no audit trail for this subject: the chain is vacuously intact because "+
				"it is empty, not because decisions were recorded and verified")
	}

	// A bundle whose verdict rests on scanners that never ran is not invalid,
	// but reading it as a clean bill of health would be a mistake.
	if b.Coverage.ScannersCompleted < b.Coverage.ScannersRequested {
		v.Problems = append(v.Problems, fmt.Sprintf(
			"%d of %d scanners did not complete (%v); the verdict rests on less "+
				"evidence than was requested",
			b.Coverage.ScannersRequested-b.Coverage.ScannersCompleted,
			b.Coverage.ScannersRequested, b.Coverage.Incomplete))
	}

	v.Valid = v.DigestMatches && v.ChainValid
	return v, nil
}

// Verification is the result of checking a bundle.
type Verification struct {
	// Valid is true when the digest matches and the audit chain is intact.
	Valid bool `json:"valid"`
	// DigestMatches reports whether the bundle is unmodified.
	DigestMatches bool `json:"digestMatches"`
	// ChainValid reports whether the audit records are intact.
	ChainValid bool `json:"chainValid"`
	// Problems describes anything a reader should weigh, including issues that
	// do not invalidate the bundle.
	Problems []string `json:"problems,omitempty"`
}

func short(h string) string {
	if len(h) <= 19 {
		return h
	}
	return h[:19]
}
