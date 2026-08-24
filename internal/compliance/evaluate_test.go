package compliance

import (
	"strings"
	"testing"
	"time"
)

// fullEvidence is a model version where every scan Cupel can run has run and
// passed. It is deliberately the best case, so tests can assert what still
// cannot be claimed even then.
func fullEvidence() Evidence {
	return Evidence{
		ScanComplete:            true,
		Verdict:                 "Approved",
		RiskScored:              true,
		SecurityScanned:         true,
		SecretsScanned:          true,
		SBOMGenerated:           true,
		AIBOMGenerated:          true,
		SignatureVerified:       true,
		PolicyRef:               "production-baseline",
		Inventoried:             true,
		ContinuousMonitoring:    true,
		AdmissionEnforcing:      true,
		ResidualRisksDocumented: true,
		BiasEvaluated:           false, // Phase 2
	}
}

func resultFor(t *testing.T, a Assessment, id string) Result {
	t.Helper()
	for _, r := range a.Results {
		if r.Control.ID == id {
			return r
		}
	}
	t.Fatalf("control %q not present in assessment", id)
	return Result{}
}

func TestCatalogIsCompleteAIRMF(t *testing.T) {
	catalog := NISTAIRMF()

	if got := len(catalog.Controls()); got != 72 {
		t.Errorf("catalog has %d controls, want the 72 AI RMF 1.0 subcategories", got)
	}

	// AI RMF 1.0 has 19 categories across the four functions.
	categories := map[string]bool{}
	for _, c := range catalog.Controls() {
		categories[c.Category] = true
	}
	if len(categories) != 19 {
		t.Errorf("catalog spans %d categories, want 19", len(categories))
	}

	counts := map[Function]int{}
	for _, c := range catalog.Controls() {
		counts[c.Function]++
	}
	for _, fn := range Functions() {
		if counts[fn] == 0 {
			t.Errorf("no controls for function %s", fn)
		}
	}
}

func TestEveryControlHasTextAndRationale(t *testing.T) {
	for _, c := range NISTAIRMF().Controls() {
		if strings.TrimSpace(c.Text) == "" {
			t.Errorf("%s has no subcategory text", c.ID)
		}
		if strings.TrimSpace(c.Rationale) == "" {
			t.Errorf("%s has no rationale; an unexplained mapping is not auditable", c.ID)
		}
		if c.Automation != AutomationNone && len(c.Evidence) == 0 {
			t.Errorf("%s claims automation %s but names no evidence", c.ID, c.Automation)
		}
	}
}

// The central honesty property: a control that no scanner can observe must
// never come back Satisfied on scan evidence alone, no matter how clean the
// scan is.
func TestOrganizationalControlsNeverSatisfiedByScanning(t *testing.T) {
	assessment := Evaluate(NISTAIRMF(), fullEvidence(), nil, Scope{}, time.Now())

	for _, result := range assessment.Results {
		if result.Control.Automation != AutomationNone {
			continue
		}
		if result.Status == StatusSatisfied {
			t.Errorf("%s is attestation-only but came back Satisfied from a scan", result.Control.ID)
		}
		if result.Status != StatusAttestationRequired {
			t.Errorf("%s = %q, want AttestationRequired with no attestation on file",
				result.Control.ID, result.Status)
		}
	}
}

// A perfect scan cannot make the framework conformant, because most of the
// framework is organizational. If this ever passes, the product is lying.
func TestPerfectScanIsNotFrameworkConformance(t *testing.T) {
	assessment := Evaluate(NISTAIRMF(), fullEvidence(), nil, Scope{}, time.Now())

	if assessment.Conformant {
		t.Fatal("a clean scan alone reported full AI RMF conformance; that is compliance theater")
	}
	if assessment.Counts[StatusAttestationRequired] == 0 {
		t.Error("no controls flagged as needing attestation")
	}

	open := len(assessment.OpenControls())
	if open < 30 {
		t.Errorf("only %d open controls after a scan-only assessment; the organizational majority is not being surfaced", open)
	}
}

// Fairness is not implied by a clean security scan. This is the mapping error
// most likely to be made, and the most damaging.
func TestBiasControlNotSatisfiedByCleanSecurityScan(t *testing.T) {
	assessment := Evaluate(NISTAIRMF(), fullEvidence(), nil, Scope{}, time.Now())

	result := resultFor(t, assessment, "MEASURE 2.11")
	if result.Status == StatusSatisfied || result.Status == StatusPartiallySatisfied {
		t.Fatalf("MEASURE 2.11 (fairness and bias) = %q from a security scan", result.Status)
	}

	for _, c := range assessment.Unmeasured {
		if c == TrustFair {
			return
		}
	}
	t.Error("fairness not listed among unmeasured characteristics despite no bias evaluation")
}

// Security and resilience is the one control Cupel exists to satisfy.
func TestSecurityControlSatisfiedByCompleteScan(t *testing.T) {
	assessment := Evaluate(NISTAIRMF(), fullEvidence(), nil, Scope{}, time.Now())

	result := resultFor(t, assessment, "MEASURE 2.7")
	if result.Status != StatusSatisfied {
		t.Fatalf("MEASURE 2.7 = %q (%s), want Satisfied", result.Status, result.Reason)
	}
}

// An incomplete scan must evidence nothing at all. Absence of findings from a
// scanner that never ran is not evidence of safety.
func TestIncompleteScanEvidencesNothing(t *testing.T) {
	evidence := fullEvidence()
	evidence.ScanComplete = false

	assessment := Evaluate(NISTAIRMF(), evidence, nil, Scope{}, time.Now())

	for _, result := range assessment.Results {
		if result.Status == StatusSatisfied {
			t.Errorf("%s came back Satisfied from an incomplete scan", result.Control.ID)
		}
	}
	if resultFor(t, assessment, "MEASURE 2.7").Status != StatusNotSatisfied {
		t.Error("the core security control did not fail on an incomplete scan")
	}
}

func TestMissingEvidenceFailsRatherThanDowngrades(t *testing.T) {
	evidence := fullEvidence()
	evidence.SBOMGenerated = false

	assessment := Evaluate(NISTAIRMF(), evidence, nil, Scope{}, time.Now())

	// MANAGE 3.1 requires SBOM among its evidence.
	result := resultFor(t, assessment, "MANAGE 3.1")
	if result.Status != StatusNotSatisfied {
		t.Errorf("MANAGE 3.1 = %q with no SBOM, want NotSatisfied", result.Status)
	}
	found := false
	for _, kind := range result.EvidenceMissing {
		if kind == EvidenceSBOM {
			found = true
		}
	}
	if !found {
		t.Errorf("missing evidence not reported; got %v", result.EvidenceMissing)
	}
}

func TestValidAttestationClosesOrganizationalControl(t *testing.T) {
	attestations := []Attestation{{
		ControlID:  "GOVERN 2.2",
		Statement:  "All ML platform staff completed AI risk management training in Q2.",
		AttestedBy: "head-of-ml-governance",
		AttestedAt: time.Now().Add(-24 * time.Hour),
		ExpiresAt:  time.Now().Add(365 * 24 * time.Hour),
	}}

	assessment := Evaluate(NISTAIRMF(), fullEvidence(), attestations, Scope{}, time.Now())

	result := resultFor(t, assessment, "GOVERN 2.2")
	if result.Status != StatusAttested {
		t.Fatalf("GOVERN 2.2 = %q, want Attested", result.Status)
	}
	if result.AttestedBy != "head-of-ml-governance" {
		t.Errorf("attester not carried through: %q", result.AttestedBy)
	}
}

// An expired attestation stops closing its control, or attestations become
// permanent and the framework becomes decorative.
func TestExpiredAttestationReopensControl(t *testing.T) {
	attestations := []Attestation{{
		ControlID:  "GOVERN 2.2",
		Statement:  "Training completed.",
		AttestedBy: "head-of-ml-governance",
		ExpiresAt:  time.Now().Add(-1 * time.Hour),
	}}

	assessment := Evaluate(NISTAIRMF(), fullEvidence(), attestations, Scope{}, time.Now())

	result := resultFor(t, assessment, "GOVERN 2.2")
	if result.Status != StatusAttestationRequired {
		t.Fatalf("GOVERN 2.2 = %q with an expired attestation, want AttestationRequired", result.Status)
	}
	if !strings.Contains(result.Warning, "expired") {
		t.Errorf("expiry not surfaced as a warning: %q", result.Warning)
	}
}

// An unattributed attestation is not an attestation.
func TestAnonymousAttestationIsRejected(t *testing.T) {
	attestations := []Attestation{{
		ControlID:  "GOVERN 2.2",
		Statement:  "Training completed.",
		AttestedBy: "   ",
	}}

	assessment := Evaluate(NISTAIRMF(), fullEvidence(), attestations, Scope{}, time.Now())

	if got := resultFor(t, assessment, "GOVERN 2.2").Status; got != StatusAttestationRequired {
		t.Fatalf("GOVERN 2.2 = %q with an unattributed attestation, want AttestationRequired", got)
	}
}

func TestNeverExpiringAttestationWarns(t *testing.T) {
	attestations := []Attestation{{
		ControlID:  "GOVERN 2.2",
		Statement:  "Training completed.",
		AttestedBy: "head-of-ml-governance",
	}}

	assessment := Evaluate(NISTAIRMF(), fullEvidence(), attestations, Scope{}, time.Now())

	result := resultFor(t, assessment, "GOVERN 2.2")
	if result.Status != StatusAttested {
		t.Fatalf("status = %q, want Attested", result.Status)
	}
	if !strings.Contains(result.Warning, "no expiry") {
		t.Errorf("a permanent attestation did not warn: %q", result.Warning)
	}
}

// Partial controls need both halves. Technical evidence alone leaves them
// visibly incomplete rather than quietly passing.
func TestPartialControlNeedsAttestationToClose(t *testing.T) {
	assessment := Evaluate(NISTAIRMF(), fullEvidence(), nil, Scope{}, time.Now())

	result := resultFor(t, assessment, "MEASURE 2.10") // privacy, partial
	if result.Status != StatusPartiallySatisfied {
		t.Fatalf("MEASURE 2.10 = %q, want PartiallySatisfied without attestation", result.Status)
	}

	withAttestation := Evaluate(NISTAIRMF(), fullEvidence(), []Attestation{{
		ControlID:  "MEASURE 2.10",
		Statement:  "Training-data privacy review completed; no PII retained.",
		AttestedBy: "privacy-office",
		ExpiresAt:  time.Now().Add(180 * 24 * time.Hour),
	}}, Scope{}, time.Now())

	if got := resultFor(t, withAttestation, "MEASURE 2.10").Status; got != StatusSatisfied {
		t.Errorf("MEASURE 2.10 = %q with evidence plus attestation, want Satisfied", got)
	}
}

func TestExclusionRequiresJustification(t *testing.T) {
	scope := Scope{NotApplicable: map[string]string{
		"GOVERN 3.1": "",
		"GOVERN 3.2": "The organization has no human-AI configuration in this deployment.",
	}}

	assessment := Evaluate(NISTAIRMF(), fullEvidence(), nil, scope, time.Now())

	if got := resultFor(t, assessment, "GOVERN 3.1").Status; got != StatusAttestationRequired {
		t.Errorf("unjustified exclusion = %q, want it rejected as AttestationRequired", got)
	}
	if got := resultFor(t, assessment, "GOVERN 3.2").Status; got != StatusNotApplicable {
		t.Errorf("justified exclusion = %q, want NotApplicable", got)
	}
}

// A fully attested, fully scanned model can reach conformance — the framework
// must be closable, or the product is useless as a governance tool.
func TestFullyAttestedModelCanReachConformance(t *testing.T) {
	catalog := NISTAIRMF()
	expiry := time.Now().Add(365 * 24 * time.Hour)

	var attestations []Attestation
	for _, control := range catalog.Controls() {
		if control.Automation == AutomationFull {
			continue // closed by evidence
		}
		attestations = append(attestations, Attestation{
			ControlID:  control.ID,
			Statement:  "Reviewed and accepted by the AI governance board.",
			AttestedBy: "ai-governance-board",
			ExpiresAt:  expiry,
		})
	}

	assessment := Evaluate(catalog, fullEvidence(), attestations, Scope{}, time.Now())

	if !assessment.Conformant {
		var open []string
		for _, r := range assessment.OpenControls() {
			open = append(open, r.Control.ID+"="+string(r.Status))
		}
		t.Fatalf("fully attested model is not conformant; open: %v", open)
	}
}

func TestUnmeasuredCharacteristicsAlwaysReported(t *testing.T) {
	assessment := Evaluate(NISTAIRMF(), fullEvidence(), nil, Scope{}, time.Now())

	if len(assessment.Unmeasured) == 0 {
		t.Fatal("no unmeasured characteristics reported; MEASURE 1.1 requires documenting what was not measured")
	}

	// Cupel is an artifact scanner: it cannot speak to validity, behavioural
	// safety, or explainability regardless of how the scan went.
	required := []TrustCharacteristic{TrustValidReliable, TrustSafe, TrustExplainable}
	for _, want := range required {
		found := false
		for _, got := range assessment.Unmeasured {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%q missing from unmeasured characteristics", want)
		}
	}
}

func TestCoverageReportsAutomationSplit(t *testing.T) {
	coverage := NISTAIRMF().Coverage()

	if coverage.Total != 72 {
		t.Errorf("total = %d, want 72", coverage.Total)
	}
	if coverage.Full+coverage.Partial+coverage.None != coverage.Total {
		t.Error("automation split does not sum to the control total")
	}
	// The honest shape of the result: most of AI RMF is organizational.
	if coverage.None <= coverage.Full+coverage.Partial {
		t.Errorf("coverage claims %d evidenceable vs %d attestation-only; AI RMF is majority organizational, so this mapping is overclaiming",
			coverage.Full+coverage.Partial, coverage.None)
	}
}

// Subcategory ordering must be numeric, or MEASURE 2.10 sorts before 2.9 in
// every report an auditor reads.
func TestControlsSortNumericallyNotLexically(t *testing.T) {
	var measure2 []string
	for _, c := range NISTAIRMF().Controls() {
		if c.Category == "MEASURE 2" {
			measure2 = append(measure2, c.ID)
		}
	}

	if len(measure2) != 13 {
		t.Fatalf("MEASURE 2 has %d subcategories, want 13", len(measure2))
	}
	if measure2[8] != "MEASURE 2.9" || measure2[9] != "MEASURE 2.10" {
		t.Errorf("ordering is lexical, not numeric: %v", measure2[8:11])
	}
}

func TestUnknownControlLookupErrors(t *testing.T) {
	if _, err := NISTAIRMF().Get("GOVERN 9.9"); err == nil {
		t.Fatal("lookup of a non-existent control succeeded")
	}
}

// A package SBOM says nothing about the model, so it must not stand in for a
// description of one. MAP 2.1 asks what task and method the system implements;
// a list of Python wheels does not answer that, and before the model bill of
// materials existed this control was being credited to an inventory entry that
// recorded a file format.
func TestPackageSBOMDoesNotSatisfyModelDescription(t *testing.T) {
	ev := fullEvidence()
	ev.AIBOMGenerated = false

	assessment := Evaluate(NISTAIRMF(), ev, nil, Scope{}, time.Now())
	r := resultFor(t, assessment, "MAP 2.1")
	if r.Status == StatusSatisfied {
		t.Fatal("MAP 2.1 must not be satisfied by a package SBOM alone")
	}
	var missing bool
	for _, kind := range r.EvidenceMissing {
		if kind == EvidenceAIBOM {
			missing = true
		}
	}
	if !missing {
		t.Fatalf("the missing evidence should name the model bill of materials, got %v",
			r.EvidenceMissing)
	}
}

// The converse: a bill of materials describing the model must actually move
// the control, or the evidence kind is decoration.
func TestModelDescriptionSatisfiesTheControl(t *testing.T) {
	assessment := Evaluate(NISTAIRMF(), fullEvidence(), nil, Scope{}, time.Now())
	r := resultFor(t, assessment, "MAP 2.1")
	// The control stays partial without an attestation — whether the declared
	// task is the right one for the deployment is not something a scanner can
	// see. What must change is that no evidence is outstanding.
	if len(r.EvidenceMissing) != 0 {
		t.Fatalf("with a model bill of materials nothing should be outstanding, got %v",
			r.EvidenceMissing)
	}
	if r.Status != StatusPartiallySatisfied {
		t.Fatalf("MAP 2.1 is partially automated, got %s", r.Status)
	}
}
