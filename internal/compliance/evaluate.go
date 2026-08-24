package compliance

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Status is the outcome of evaluating one control for one model version.
type Status string

const (
	// StatusSatisfied — the control's intent is met, either by technical
	// evidence Cupel produced or by evidence plus a current attestation.
	StatusSatisfied Status = "Satisfied"
	// StatusPartiallySatisfied — Cupel evidences part of the control, but the
	// remainder is organizational and has not been attested.
	StatusPartiallySatisfied Status = "PartiallySatisfied"
	// StatusNotSatisfied — Cupel looked and the evidence is missing or failing.
	StatusNotSatisfied Status = "NotSatisfied"
	// StatusAttested — no technical evidence is possible; a named person
	// attested to the control and the attestation has not expired.
	StatusAttested Status = "Attested"
	// StatusAttestationRequired — the control needs a human attestation and
	// none is on file, or the one on file has expired.
	StatusAttestationRequired Status = "AttestationRequired"
	// StatusNotApplicable — scoped out of the profile with a justification.
	StatusNotApplicable Status = "NotApplicable"
)

// Open reports whether the status leaves work outstanding.
func (s Status) Open() bool {
	switch s {
	case StatusSatisfied, StatusAttested, StatusNotApplicable:
		return false
	default:
		return true
	}
}

// TrustCharacteristic is one of the seven characteristics of trustworthy AI
// named in AI RMF 1.0.
type TrustCharacteristic string

const (
	TrustValidReliable   TrustCharacteristic = "Valid and Reliable"
	TrustSafe            TrustCharacteristic = "Safe"
	TrustSecureResilient TrustCharacteristic = "Secure and Resilient"
	TrustAccountable     TrustCharacteristic = "Accountable and Transparent"
	TrustExplainable     TrustCharacteristic = "Explainable and Interpretable"
	TrustPrivacy         TrustCharacteristic = "Privacy-Enhanced"
	TrustFair            TrustCharacteristic = "Fair with Harmful Bias Managed"
)

// TrustCharacteristics returns all seven in the order AI RMF presents them.
func TrustCharacteristics() []TrustCharacteristic {
	return []TrustCharacteristic{
		TrustValidReliable, TrustSafe, TrustSecureResilient, TrustAccountable,
		TrustExplainable, TrustPrivacy, TrustFair,
	}
}

// Evidence is what Cupel observed for one model version. The controller fills
// this in from a ModelSecurityReport; keeping it a plain struct makes the
// evaluator pure and testable without a cluster.
type Evidence struct {
	// ScanComplete reports whether every selected scanner finished. An
	// incomplete scan cannot evidence anything: absence of findings from a
	// scanner that never ran is not evidence of safety.
	ScanComplete bool
	// Verdict is Approved, Quarantined, ReviewRequired, or empty.
	Verdict string
	// RiskScored reports whether a consolidated risk score was produced.
	RiskScored bool
	// SecurityScanned reports that malware, vulnerability, and model-format
	// analysis all ran to completion.
	SecurityScanned bool
	// SecretsScanned reports that credential detection ran.
	SecretsScanned bool
	// SBOMGenerated reports that a bill of materials was produced.
	SBOMGenerated bool
	// AIBOMGenerated reports that a bill of materials describing the model
	// itself was produced. A scanner that ran and described nothing does not
	// set this, because a control asking for a description is not satisfied
	// by an empty one.
	AIBOMGenerated bool
	// SignatureVerified reports provenance verification against a trusted
	// publisher.
	SignatureVerified bool
	// PolicyRef names the governing ArtifactScanPolicy, if any.
	PolicyRef string
	// Inventoried reports that a ModelSecurityReport exists for this version.
	Inventoried bool
	// ContinuousMonitoring reports that a connector rescans this model on a
	// cadence rather than scanning once at registration.
	ContinuousMonitoring bool
	// AdmissionEnforcing reports that the gate is in Enforce mode, which is
	// what makes revocation an actual control rather than a record.
	AdmissionEnforcing bool
	// ResidualRisksDocumented reports that every accepted risk carries a
	// reason and an approver.
	ResidualRisksDocumented bool
	// BiasEvaluated reports that fairness testing ran. Set from evidence
	// outside the artifact scan, which is where that testing lives.
	BiasEvaluated bool
}

// Attestation is a human statement closing a control Cupel cannot observe.
type Attestation struct {
	// ControlID the attestation covers.
	ControlID string
	// Statement is what is being attested.
	Statement string
	// AttestedBy names the accountable person or team. Required: an
	// unattributed attestation is not an attestation.
	AttestedBy string
	// AttestedAt is when it was made.
	AttestedAt time.Time
	// ExpiresAt bounds it. Zero means it never expires, which the evaluator
	// flags rather than silently honouring forever.
	ExpiresAt time.Time
	// EvidenceURI optionally points at supporting documentation.
	EvidenceURI string
}

// Valid reports whether an attestation can close a control at time now.
func (a Attestation) Valid(now time.Time) (bool, string) {
	if strings.TrimSpace(a.AttestedBy) == "" {
		return false, "attestation has no named attester"
	}
	if strings.TrimSpace(a.Statement) == "" {
		return false, "attestation has no statement"
	}
	if !a.ExpiresAt.IsZero() && now.After(a.ExpiresAt) {
		return false, fmt.Sprintf("attestation expired on %s", a.ExpiresAt.UTC().Format(time.RFC3339))
	}
	return true, ""
}

// Result is the evaluation of one control.
type Result struct {
	Control Control
	Status  Status
	// Reason explains the status in terms an auditor can follow.
	Reason string
	// EvidenceSeen lists the evidence kinds actually observed.
	EvidenceSeen []EvidenceKind
	// EvidenceMissing lists the ones the mapping expects but did not find.
	EvidenceMissing []EvidenceKind
	// AttestedBy is carried through when an attestation closed the control.
	AttestedBy string
	// Warning surfaces something the auditor should look at even though the
	// control is not open — an attestation with no expiry, for instance.
	Warning string
}

// Assessment is the full evaluation for one model version.
type Assessment struct {
	Framework Framework
	Coverage  Coverage
	Results   []Result
	// Unmeasured is the set of trustworthiness characteristics this scan did
	// not evaluate. Recording it is what MEASURE 1.1 actually asks for, and
	// stating it plainly is the difference between a report and a claim.
	Unmeasured []TrustCharacteristic
	// Counts by status.
	Counts map[Status]int
	// Conformant reports whether no control is left open.
	Conformant bool
}

// OpenControls returns the controls still requiring work, worst first.
func (a Assessment) OpenControls() []Result {
	var out []Result
	for _, r := range a.Results {
		if r.Status.Open() {
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return statusSeverity(out[i].Status) > statusSeverity(out[j].Status)
	})
	return out
}

func statusSeverity(s Status) int {
	switch s {
	case StatusNotSatisfied:
		return 3
	case StatusPartiallySatisfied:
		return 2
	case StatusAttestationRequired:
		return 1
	default:
		return 0
	}
}

// Summary renders a one-line result for logs and status messages.
func (a Assessment) Summary() string {
	return fmt.Sprintf("%s: %d satisfied, %d attested, %d partial, %d awaiting attestation, %d not satisfied, %d n/a",
		a.Framework,
		a.Counts[StatusSatisfied], a.Counts[StatusAttested],
		a.Counts[StatusPartiallySatisfied], a.Counts[StatusAttestationRequired],
		a.Counts[StatusNotSatisfied], a.Counts[StatusNotApplicable])
}

// Scope declares which controls a profile considers out of scope.
type Scope struct {
	// NotApplicable maps control ID to the justification for excluding it.
	// A control cannot be scoped out without one.
	NotApplicable map[string]string
}

// Evaluate assesses a model version against a framework.
//
// The rule that keeps this honest: technical evidence alone can only satisfy
// a control whose Automation is Full. Anything Partial still needs a human to
// close the organizational remainder, and anything marked None can only ever
// be Attested. Nothing infers one trustworthiness characteristic from
// another — a clean security scan says nothing about bias.
func Evaluate(catalog *Catalog, ev Evidence, attestations []Attestation, scope Scope, now time.Time) Assessment {
	byControl := map[string]Attestation{}
	for _, a := range attestations {
		byControl[a.ControlID] = a
	}

	present := observedEvidence(ev)

	assessment := Assessment{
		Framework:  catalog.Framework,
		Coverage:   catalog.Coverage(),
		Counts:     map[Status]int{},
		Unmeasured: unmeasuredCharacteristics(ev),
	}

	for _, ctrl := range catalog.Controls() {
		result := evaluateControl(ctrl, present, byControl, scope, now)
		assessment.Results = append(assessment.Results, result)
		assessment.Counts[result.Status]++
	}

	assessment.Conformant = len(assessment.OpenControls()) == 0
	return assessment
}

func evaluateControl(ctrl Control, present map[EvidenceKind]bool, attestations map[string]Attestation, scope Scope, now time.Time) Result {
	result := Result{Control: ctrl}

	// Scoping out is legitimate, but only with a stated justification —
	// an unexplained exclusion is how frameworks get gamed.
	if justification, ok := scope.NotApplicable[ctrl.ID]; ok {
		if strings.TrimSpace(justification) == "" {
			result.Status = StatusAttestationRequired
			result.Reason = "declared not applicable without a justification; scoping a control out requires one"
			return result
		}
		result.Status = StatusNotApplicable
		result.Reason = justification
		return result
	}

	for _, kind := range ctrl.Evidence {
		if present[kind] {
			result.EvidenceSeen = append(result.EvidenceSeen, kind)
		} else {
			result.EvidenceMissing = append(result.EvidenceMissing, kind)
		}
	}

	attestation, hasAttestation := attestations[ctrl.ID]
	attestationValid := false
	if hasAttestation {
		var why string
		attestationValid, why = attestation.Valid(now)
		if !attestationValid {
			result.Warning = why
		} else {
			result.AttestedBy = attestation.AttestedBy
			if attestation.ExpiresAt.IsZero() {
				result.Warning = "attestation has no expiry; a permanent attestation is not periodically re-examined"
			}
		}
	}

	switch ctrl.Automation {
	case AutomationNone:
		// No scan result can speak to this control. Attestation is the only
		// path, and its absence is reported rather than papered over.
		if attestationValid {
			result.Status = StatusAttested
			result.Reason = fmt.Sprintf("attested by %s: %s", attestation.AttestedBy, attestation.Statement)
			return result
		}
		result.Status = StatusAttestationRequired
		result.Reason = ctrl.Rationale
		return result

	case AutomationFull:
		if len(result.EvidenceMissing) > 0 {
			result.Status = StatusNotSatisfied
			result.Reason = fmt.Sprintf("expected evidence not produced: %s", joinKinds(result.EvidenceMissing))
			return result
		}
		result.Status = StatusSatisfied
		result.Reason = ctrl.Rationale
		return result

	default: // AutomationPartial
		if len(result.EvidenceMissing) > 0 {
			result.Status = StatusNotSatisfied
			result.Reason = fmt.Sprintf("expected evidence not produced: %s", joinKinds(result.EvidenceMissing))
			return result
		}
		if attestationValid {
			result.Status = StatusSatisfied
			result.Reason = fmt.Sprintf("technical evidence (%s) plus attestation by %s",
				joinKinds(result.EvidenceSeen), attestation.AttestedBy)
			return result
		}
		result.Status = StatusPartiallySatisfied
		result.Reason = fmt.Sprintf("Cupel evidences %s; the organizational remainder is unattested. %s",
			joinKinds(result.EvidenceSeen), ctrl.Rationale)
		return result
	}
}

// observedEvidence turns raw scan facts into the evidence kinds the control
// mapping refers to.
func observedEvidence(ev Evidence) map[EvidenceKind]bool {
	// An incomplete scan evidences nothing. Every kind below is gated on it
	// so a half-finished scan cannot satisfy a single control.
	if !ev.ScanComplete {
		return map[EvidenceKind]bool{}
	}

	verdictDecided := ev.Verdict != "" && ev.Verdict != "Unknown"

	return map[EvidenceKind]bool{
		EvidenceInventory:    ev.Inventoried,
		EvidenceSecurityScan: ev.SecurityScanned,
		EvidenceSBOM:         ev.SBOMGenerated,
		EvidenceAIBOM:        ev.AIBOMGenerated,
		EvidenceProvenance:   ev.SignatureVerified,
		EvidenceSecrets:      ev.SecretsScanned,
		EvidencePolicy:       ev.PolicyRef != "",
		EvidenceVerdict:      verdictDecided,
		EvidenceRiskScore:    ev.RiskScored,
		EvidenceResidualRisk: ev.ResidualRisksDocumented,
		EvidenceScanHistory:  ev.ContinuousMonitoring,
		EvidenceRevocation:   ev.AdmissionEnforcing,
		// Cupel always records what it did not measure, so once a scan is
		// complete this evidence exists by construction.
		EvidenceCoverageGap: true,
		EvidenceBiasEval:    ev.BiasEvaluated,
	}
}

// unmeasuredCharacteristics reports which of the seven trustworthiness
// characteristics this scan did not evaluate.
//
// Cupel is an artifact scanner, so it speaks to security, and partially to
// privacy and accountability. It says nothing about validity, safety in the
// behavioural sense, explainability, or fairness — and listing that is the
// point, not a caveat.
func unmeasuredCharacteristics(ev Evidence) []TrustCharacteristic {
	var out []TrustCharacteristic

	out = append(out, TrustValidReliable, TrustSafe, TrustExplainable)

	if !ev.BiasEvaluated {
		out = append(out, TrustFair)
	}
	if !ev.ScanComplete || !ev.SecurityScanned {
		out = append(out, TrustSecureResilient)
	}
	if !ev.ScanComplete || !ev.SecretsScanned {
		out = append(out, TrustPrivacy)
	}
	if !ev.ScanComplete || !ev.SignatureVerified {
		out = append(out, TrustAccountable)
	}
	return out
}

func joinKinds(kinds []EvidenceKind) string {
	if len(kinds) == 0 {
		return "none"
	}
	parts := make([]string, len(kinds))
	for i, k := range kinds {
		parts[i] = string(k)
	}
	return strings.Join(parts, ", ")
}
