package evidence

import (
	"strings"
	"testing"
	"time"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/audit"
)

func sampleInput() Input {
	base := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	// A realistic chain: this subject's records are scattered through a log
	// shared with every other model in the cluster. A fixture where the whole
	// chain belongs to one subject is the one shape that hides the difference
	// between a chain and an excerpt.
	subjects := []string{"other/v1", "fraud/v3", "spam/v2", "fraud/v3", "other/v1", "fraud/v3"}
	var chain []audit.Record
	var prev *audit.Record
	for i, subj := range subjects {
		r := audit.Seal(audit.Record{
			Time: base.Add(time.Duration(i) * time.Minute),
			Type: audit.EventVerdictIssued, Subject: subj, Actor: "system",
		}, prev)
		chain = append(chain, r)
		prev = &chain[len(chain)-1]
	}
	cp := audit.Head(chain)

	return Input{
		Now:      base,
		Producer: "cupel 0.1.0",
		Subject: Subject{
			Model: "fraud", Version: "v3",
			ArtifactURI: "s3://models/fraud/v3", ArtifactDigest: "sha256:abc",
		},
		Verdict: Verdict{
			Decision: "Approved", RiskScore: 12, Policy: "production-baseline",
			ScannedAt: base, Trigger: "Registry",
		},
		Scanners: []ScannerRun{
			{Name: "model-inspector", Completed: true, Findings: 1},
			{Name: "clamav", Completed: true},
			{Name: "provenance", Completed: true},
		},
		AuditChain:      chain,
		AuditCheckpoint: &cp,
	}
}

func TestBundleVerifiesWhenIntact(t *testing.T) {
	b, err := Build(sampleInput())
	if err != nil {
		t.Fatal(err)
	}
	v, err := Verify(b)
	if err != nil {
		t.Fatal(err)
	}
	if !v.Valid {
		t.Fatalf("a freshly built bundle must verify: %v", v.Problems)
	}
	if !strings.HasPrefix(b.Digest, "sha256:") {
		t.Fatalf("digest should be prefixed, got %q", b.Digest)
	}
}

// The point of the digest: an edited bundle stops verifying. Somebody who
// trusts nothing about its provenance can still establish that much.
func TestEditedBundleFailsVerification(t *testing.T) {
	b, _ := Build(sampleInput())

	b.Verdict.Decision = "Approved"
	b.Verdict.RiskScore = 0 // was 12

	v, err := Verify(b)
	if err != nil {
		t.Fatal(err)
	}
	if v.Valid || v.DigestMatches {
		t.Fatal("changing the risk score must break the digest")
	}
	if !strings.Contains(strings.Join(v.Problems, " "), "modified") {
		t.Fatalf("the problem should say it was modified, got %v", v.Problems)
	}
}

func TestChangingAnAcceptanceApproverIsDetected(t *testing.T) {
	in := sampleInput()
	in.Acceptances = []Acceptance{{
		FindingIDs: []string{"CVE-2025-1"}, Reason: "compensating control",
		ApprovedBy: "alice@davano.net", ApprovedAt: in.Now, Signed: true,
	}}
	b, _ := Build(in)

	b.Acceptances[0].ApprovedBy = "bob@davano.net"
	v, _ := Verify(b)
	if v.Valid {
		t.Fatal("rewriting who accepted a risk must invalidate the bundle")
	}
}

// Tampering with an embedded audit record must be caught by the record's own
// hash, not only by the outer digest. This is the part of the audit trail a
// bundle can prove about itself, offline, with nothing else to hand.
func TestTamperedAuditRecordIsCaught(t *testing.T) {
	b, _ := Build(sampleInput())
	b.Audit.Records[1].Actor = "someone-else"
	// Re-digest so the outer hash matches; only the chain can catch this now.
	fixed, err := b.computeDigest()
	if err != nil {
		t.Fatal(err)
	}
	b.Digest = fixed

	v, _ := Verify(b)
	if v.DigestMatches != true {
		t.Fatal("the digest was recomputed and should match")
	}
	if v.RecordsIntact {
		t.Fatal("a rewritten record must be caught by its own hash even when the " +
			"outer digest was recomputed")
	}
	if v.Valid {
		t.Fatal("a bundle with a broken chain is not valid")
	}
}

// A verdict resting on scanners that never ran is the failure an authorizing
// official most needs flagged, because it looks identical to a clean result.
func TestIncompleteScannersAreSurfaced(t *testing.T) {
	in := sampleInput()
	in.Scanners = append(in.Scanners,
		ScannerRun{Name: "trivy", Completed: false, Message: "image pull failed"})
	b, _ := Build(in)

	if b.Coverage.ScannersCompleted != 3 || b.Coverage.ScannersRequested != 4 {
		t.Fatalf("coverage counts wrong: %+v", b.Coverage)
	}
	if len(b.Coverage.Incomplete) != 1 || b.Coverage.Incomplete[0] != "trivy" {
		t.Fatalf("the incomplete scanner should be named, got %v", b.Coverage.Incomplete)
	}

	v, _ := Verify(b)
	joined := strings.Join(v.Problems, " ")
	if !strings.Contains(joined, "did not complete") {
		t.Fatalf("verification should surface incomplete coverage, got %v", v.Problems)
	}
	// It is a caveat, not a forgery: the bundle is still authentic.
	if !v.DigestMatches {
		t.Fatal("incomplete coverage must not be reported as tampering")
	}
}

// Every bundle must state what the tool structurally cannot assess. A clean
// report that omits this invites the reader to assume it was covered.
func TestOutOfScopeIsAlwaysStated(t *testing.T) {
	b, _ := Build(sampleInput())
	if len(b.Coverage.OutOfScope) == 0 {
		t.Fatal("a bundle must always declare what it cannot assess")
	}
	joined := strings.Join(b.Coverage.OutOfScope, " ")
	for _, required := range []string{"AML.T0018.000", "AML.T0020", "behavioural"} {
		if !strings.Contains(joined, required) {
			t.Errorf("the out-of-scope statement should mention %q", required)
		}
	}
}

// Techniques may only be claimed for scanners that actually completed.
func TestTechniquesOnlyClaimedForScannersThatRan(t *testing.T) {
	in := sampleInput()
	for i := range in.Scanners {
		in.Scanners[i].Completed = false
	}
	b, _ := Build(in)
	if len(b.Controls.TechniquesEvidenced) != 0 {
		t.Fatalf("no scanner completed, so no technique is evidenced, got %v",
			b.Controls.TechniquesEvidenced)
	}
}

func TestTechniquesClaimedWhenScannersRan(t *testing.T) {
	b, _ := Build(sampleInput())
	if len(b.Controls.TechniquesEvidenced) == 0 {
		t.Fatal("completed scanners should evidence at least one technique")
	}
	if b.Controls.ATLASVersion == "" {
		t.Fatal("the bundle must name the ATLAS release it mapped against")
	}
	if b.Controls.ATLAS.OutOfScope == 0 {
		t.Fatal("the ATLAS summary should carry the out-of-scope count")
	}
}

// Building the same input twice must produce the same digest, or a bundle
// cannot be diffed or re-verified after a round trip.
func TestBundleDigestIsDeterministic(t *testing.T) {
	a, _ := Build(sampleInput())
	c, _ := Build(sampleInput())
	if a.Digest != c.Digest {
		t.Fatal("the same evidence must produce the same digest")
	}
}

func TestUnsignedAcceptanceIsRecordedAsSuch(t *testing.T) {
	in := sampleInput()
	in.Acceptances = []Acceptance{{
		Reason: "reviewed", ApprovedBy: "unattributed", ApprovedAt: in.Now, Signed: false,
	}}
	b, _ := Build(in)
	if b.Acceptances[0].Signed {
		t.Fatal("an unsigned acceptance must not be recorded as signed")
	}
}

func TestFindingsSurviveIntoTheBundle(t *testing.T) {
	in := sampleInput()
	in.Findings = []securityv1alpha1.Finding{{
		ID: "TESS-PICKLE-001", Severity: "Critical", Title: "Pickle executes code",
	}}
	b, _ := Build(in)
	if len(b.Findings) != 1 || b.Findings[0].ID != "TESS-PICKLE-001" {
		t.Fatal("findings must be carried in the bundle, not summarised away")
	}
}

// An empty chain verifies vacuously. Without saying so, a bundle carrying no
// audit trail reads exactly like one carrying a clean trail — and a reader of
// an evidence bundle is the person least able to check which they have.
func TestEmptyAuditTrailIsNotReportedAsAssurance(t *testing.T) {
	in := sampleInput()
	in.AuditChain = nil
	in.AuditCheckpoint = nil

	b, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	if b.Audit.Present {
		t.Fatal("there are no records, so Present must be false")
	}
	if !b.Audit.ChainValid {
		t.Fatal("an empty chain is still internally consistent")
	}

	v, err := Verify(b)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(v.Problems, " ")
	if !strings.Contains(joined, "no audit trail") {
		t.Fatalf("verification must surface the absence, got %v", v.Problems)
	}
	// The bundle is still authentic — an absent trail is a caveat, not forgery.
	if !v.DigestMatches {
		t.Fatal("a missing audit trail must not be reported as tampering")
	}
}

func TestPopulatedAuditTrailIsMarkedPresent(t *testing.T) {
	b, err := Build(sampleInput())
	if err != nil {
		t.Fatal(err)
	}
	if !b.Audit.Present {
		t.Fatal("the sample carries records, so Present must be true")
	}
	v, _ := Verify(b)
	if strings.Contains(strings.Join(v.Problems, " "), "no audit trail") {
		t.Fatal("a populated trail must not be reported as absent")
	}
}
