package controller

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/audit"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/policy"
)

// The audit package and its CRDs existed for a while with nothing writing to
// them, which meant the AU-9 control mapping asserted a hash chain that was
// never populated. These tests exist so that cannot recur silently.
func TestVerdictIsRecordedInTheAuditChain(t *testing.T) {
	scheme := digestTestScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := &ArtifactScanReconciler{Client: c, Scheme: scheme, AuditNamespace: "cupel-system"}

	scan := &securityv1alpha1.ArtifactScan{
		ObjectMeta: metav1.ObjectMeta{Name: "s1", Namespace: "cupel-system"},
		Spec: securityv1alpha1.ArtifactScanSpec{
			ModelName: "fraud", ModelVersion: "v3",
			Trigger: "Registry", TriggeredBy: "mlflow/local",
		},
		Status: securityv1alpha1.ArtifactScanStatus{ScannedDigest: "sha256:measured"},
	}
	r.recordVerdict(context.Background(), scan, policy.Evaluation{Verdict: "Quarantined", RiskScore: 87})

	rec := &audit.Recorder{Client: c, Namespace: "cupel-system"}
	records, _, err := rec.Chain(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("the verdict should have produced one audit record, got %d", len(records))
	}

	got := records[0]
	if got.Type != audit.EventVerdictIssued {
		t.Errorf("wrong event type: %s", got.Type)
	}
	if got.Subject != "fraud/v3" {
		t.Errorf("subject should identify the model version, got %q", got.Subject)
	}
	if got.Detail["verdict"] != "Quarantined" || got.Detail["risk"] != "87" {
		t.Errorf("the decision itself must be recorded, got %v", got.Detail)
	}
	// Why the scan ran changes what its verdict means.
	if got.Detail["trigger"] != "Registry" {
		t.Errorf("trigger should travel with the verdict, got %q", got.Detail["trigger"])
	}
	// The measured digest, not the declared one: a verdict belongs to bytes.
	if got.Detail["digest"] != "sha256:measured" {
		t.Errorf("the record must bind to the scanned digest, got %q", got.Detail["digest"])
	}

	if v := audit.Verify(records, nil); !v.Valid {
		t.Fatalf("the written chain must verify: %v", v.Problems)
	}
}

// Recording is best-effort: losing an audit entry must never also lose the
// verdict, since a gap in the chain is detectable and a missing scan is not.
func TestRecordingDisabledDoesNotBreakTheScan(t *testing.T) {
	scheme := digestTestScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := &ArtifactScanReconciler{Client: c, Scheme: scheme} // no AuditNamespace

	scan := &securityv1alpha1.ArtifactScan{
		ObjectMeta: metav1.ObjectMeta{Name: "s1", Namespace: "cupel-system"},
		Spec:       securityv1alpha1.ArtifactScanSpec{ModelName: "m", ModelVersion: "1"},
	}
	// Must not panic and must not write anything.
	r.recordVerdict(context.Background(), scan, policy.Evaluation{Verdict: "Approved"})

	var list securityv1alpha1.AuditRecordList
	if err := c.List(context.Background(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 0 {
		t.Fatal("recording is disabled, so nothing should have been written")
	}
}

// Successive verdicts must chain, or the log is a pile of records rather than
// something tampering is evident against.
func TestSuccessiveVerdictsChain(t *testing.T) {
	scheme := digestTestScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := &ArtifactScanReconciler{Client: c, Scheme: scheme, AuditNamespace: "cupel-system"}
	ctx := context.Background()

	for i, verdict := range []string{"ReviewRequired", "Approved", "Quarantined"} {
		scan := &securityv1alpha1.ArtifactScan{
			ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "cupel-system"},
			Spec:       securityv1alpha1.ArtifactScanSpec{ModelName: "m", ModelVersion: "1"},
		}
		r.recordVerdict(ctx, scan, policy.Evaluation{Verdict: verdict, RiskScore: int32(i)})
	}

	rec := &audit.Recorder{Client: c, Namespace: "cupel-system"}
	records, cp, err := rec.Chain(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 {
		t.Fatalf("want 3 linked records, got %d", len(records))
	}
	if cp == nil || cp.Length != 3 {
		t.Fatal("the checkpoint must track the chain, or truncation stops being detectable")
	}
	if v := audit.Verify(records, cp); !v.Valid {
		t.Fatalf("chain should verify against its checkpoint: %v", v.Problems)
	}
}
