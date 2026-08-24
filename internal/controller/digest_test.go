package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/naming"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/policy"
)

func digestTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := securityv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

// The admission gate refuses a verdict whose digest does not match the bytes
// being deployed — but only if it has a digest to compare. The measurement is
// taken by the fetch step, lands as an annotation on the ArtifactScanReport,
// and has to travel up to the ModelSecurityReport for the gate to see it.
//
// That last hop did not exist: the gate's replay check read a field nothing
// ever wrote, so the comparison short-circuited and every approved verdict was
// replayable onto different bytes at the same URI. This pins the whole chain.
func TestScannedDigestReachesTheModelReport(t *testing.T) {
	const (
		namespace = "cupel-system"
		scanName  = "scan-fraud-v1"
		digest    = "sha256:1f0e3dad99908345f7439f8ffabdffc4"
	)

	scan := &securityv1alpha1.ArtifactScan{
		ObjectMeta: metav1.ObjectMeta{Name: scanName, Namespace: namespace},
		Spec: securityv1alpha1.ArtifactScanSpec{
			ModelName:    "fraud",
			ModelVersion: "v1",
			// The registry declared no digest, which is the normal case.
			Artifact: securityv1alpha1.ArtifactRef{URI: "s3://models/fraud/v1"},
		},
	}

	scanReport := &securityv1alpha1.ArtifactScanReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      naming.ScanReport(scanName, "clamav"),
			Namespace: namespace,
			Labels:    map[string]string{LabelScan: scanName},
			// What the publish step records after fetch measures the bytes.
			Annotations: map[string]string{AnnotationArtifactDigest: digest},
		},
		Scanner: "clamav",
		ScanRef: scanName,
		Summary: securityv1alpha1.ScannerResult{Scanner: "clamav", Status: "Passed"},
	}

	c := fake.NewClientBuilder().
		WithScheme(digestTestScheme(t)).
		WithObjects(scan, scanReport).
		WithStatusSubresource(
			&securityv1alpha1.ArtifactScan{},
			&securityv1alpha1.ModelSecurityReport{},
		).
		Build()
	r := &ArtifactScanReconciler{Client: c, Scheme: digestTestScheme(t)}

	ctx := context.Background()
	if _, _, err := r.collectResults(ctx, scan, []string{"clamav"}); err != nil {
		t.Fatalf("collectResults: %v", err)
	}
	if scan.Status.ScannedDigest != digest {
		t.Fatalf("scan.Status.ScannedDigest = %q, want the measured digest %q",
			scan.Status.ScannedDigest, digest)
	}

	if err := r.upsertModelSecurityReport(ctx, scan, policy.Evaluation{
		Verdict:   securityv1alpha1.VerdictApproved,
		RiskScore: 0,
	}); err != nil {
		t.Fatalf("upsertModelSecurityReport: %v", err)
	}

	var model securityv1alpha1.ModelSecurityReport
	key := client.ObjectKey{Name: ModelReportName("fraud", "v1"), Namespace: namespace}
	if err := c.Get(ctx, key, &model); err != nil {
		t.Fatalf("get model report: %v", err)
	}
	if model.Spec.Artifact.Digest != digest {
		t.Errorf("model report digest = %q, want %q — the gate cannot pin a verdict without it",
			model.Spec.Artifact.Digest, digest)
	}
}

// A Job can succeed, have its TTL delete it, and never produce a report — the
// publish step gets OOM-killed, or is denied by RBAC, or loses a write race.
// After that there is no Job to read a status from and no report to read a
// result from, so the scan requeued every 15 seconds forever while the
// evidence was already garbage-collected. Nothing surfaced; the scan simply
// never finished. A deadline turns that into a visible failure.
func TestStuckScanFailsAtItsDeadline(t *testing.T) {
	const namespace = "cupel-system"

	longAgo := metav1.NewTime(time.Now().Add(-3 * time.Hour))
	scan := &securityv1alpha1.ArtifactScan{
		ObjectMeta: metav1.ObjectMeta{Name: "scan-stuck", Namespace: namespace},
		Spec: securityv1alpha1.ArtifactScanSpec{
			ModelName:    "fraud",
			ModelVersion: "v1",
			Artifact:     securityv1alpha1.ArtifactRef{URI: "s3://models/fraud/v1"},
			Scanners:     []string{"clamav"},
		},
		Status: securityv1alpha1.ArtifactScanStatus{
			Phase:     "Scanning",
			StartTime: &longAgo,
		},
	}

	// Deliberately no Job and no ArtifactScanReport: the TTL-deleted state, in
	// which the controller happily recreates the Job and waits again — forever,
	// re-running the same scan every time the TTL sweeps it.
	c := fake.NewClientBuilder().
		WithScheme(digestTestScheme(t)).
		WithObjects(scan).
		WithStatusSubresource(&securityv1alpha1.ArtifactScan{}).
		Build()
	r := &ArtifactScanReconciler{
		Client:    c,
		Scheme:    digestTestScheme(t),
		JobConfig: JobConfig{OperatorImage: "cupel:test", ServiceAccount: "cupel-scanner"},
	}

	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: client.ObjectKey{Name: "scan-stuck", Namespace: namespace},
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.RequeueAfter != 0 {
		t.Errorf("scan past its deadline requeued again after %s", res.RequeueAfter)
	}

	var got securityv1alpha1.ArtifactScan
	if err := c.Get(context.Background(), client.ObjectKey{Name: "scan-stuck", Namespace: namespace}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Phase != "Failed" {
		t.Errorf("phase = %q, want Failed", got.Status.Phase)
	}
	// An unfinished scan is not evidence of safety.
	if got.Status.Verdict == securityv1alpha1.VerdictApproved {
		t.Error("a scan that never completed was marked Approved")
	}
}

// A scan still inside its deadline must keep waiting rather than being failed
// for being slow.
func TestRunningScanInsideDeadlineKeepsWaiting(t *testing.T) {
	const namespace = "cupel-system"

	recent := metav1.NewTime(time.Now().Add(-1 * time.Minute))
	scan := &securityv1alpha1.ArtifactScan{
		ObjectMeta: metav1.ObjectMeta{Name: "scan-running", Namespace: namespace},
		Spec: securityv1alpha1.ArtifactScanSpec{
			ModelName:    "fraud",
			ModelVersion: "v1",
			Artifact:     securityv1alpha1.ArtifactRef{URI: "s3://models/fraud/v1"},
			Scanners:     []string{"clamav"},
		},
		Status: securityv1alpha1.ArtifactScanStatus{Phase: "Scanning", StartTime: &recent},
	}

	c := fake.NewClientBuilder().
		WithScheme(digestTestScheme(t)).
		WithObjects(scan).
		WithStatusSubresource(&securityv1alpha1.ArtifactScan{}).
		Build()
	r := &ArtifactScanReconciler{
		Client:    c,
		Scheme:    digestTestScheme(t),
		JobConfig: JobConfig{OperatorImage: "cupel:test", ServiceAccount: "cupel-scanner"},
	}

	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: client.ObjectKey{Name: "scan-running", Namespace: namespace},
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Error("a scan inside its deadline stopped being requeued")
	}

	var got securityv1alpha1.ArtifactScan
	if err := c.Get(context.Background(), client.ObjectKey{Name: "scan-running", Namespace: namespace}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Phase == "Failed" {
		t.Errorf("a scan running for a minute was failed: %s", got.Status.Message)
	}
}

// Scan reports carry the full findings array and are named deterministically
// from (scan, scanner). Nothing owned them, so they survived their scan
// forever: etcd grew without bound, and a report left over from an earlier run
// of the same scan name was indistinguishable from the current one's result.
func TestScanReportsAreAdoptedByTheirScan(t *testing.T) {
	const (
		namespace = "cupel-system"
		scanName  = "scan-adopt"
	)

	scan := &securityv1alpha1.ArtifactScan{
		ObjectMeta: metav1.ObjectMeta{Name: scanName, Namespace: namespace, UID: "scan-uid-1"},
		Spec: securityv1alpha1.ArtifactScanSpec{
			ModelName: "fraud", ModelVersion: "v1",
			Artifact: securityv1alpha1.ArtifactRef{URI: "s3://models/fraud/v1"},
		},
	}
	orphan := &securityv1alpha1.ArtifactScanReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      naming.ScanReport(scanName, "clamav"),
			Namespace: namespace,
			Labels:    map[string]string{LabelScan: scanName},
		},
		Scanner: "clamav",
		ScanRef: scanName,
		Summary: securityv1alpha1.ScannerResult{Scanner: "clamav", Status: "Passed"},
	}

	c := fake.NewClientBuilder().
		WithScheme(digestTestScheme(t)).
		WithObjects(scan, orphan).
		WithStatusSubresource(&securityv1alpha1.ArtifactScan{}).
		Build()
	r := &ArtifactScanReconciler{Client: c, Scheme: digestTestScheme(t)}

	if _, _, err := r.collectResults(context.Background(), scan, []string{"clamav"}); err != nil {
		t.Fatalf("collectResults: %v", err)
	}

	var got securityv1alpha1.ArtifactScanReport
	key := client.ObjectKey{Name: orphan.Name, Namespace: namespace}
	if err := c.Get(context.Background(), key, &got); err != nil {
		t.Fatal(err)
	}
	if !metav1.IsControlledBy(&got, scan) {
		t.Errorf("report has no controller reference to its scan; owners = %+v", got.OwnerReferences)
	}
}

// Accepting a risk has to actually change the verdict. It did not: a finished
// scan returned immediately on its terminal phase, so an ArtifactException sat
// in the cluster affecting nothing and the button that created it looked
// broken — because it was. This pins the disposition end to end.
func TestAcceptingRiskClearsTheVerdict(t *testing.T) {
	const ns = "cupel-system"

	risk := int32(60)
	scan := &securityv1alpha1.ArtifactScan{
		ObjectMeta: metav1.ObjectMeta{Name: "scan-quarantined", Namespace: ns},
		Spec: securityv1alpha1.ArtifactScanSpec{
			ModelName: "fraud", ModelVersion: "v1",
			Artifact: securityv1alpha1.ArtifactRef{URI: "s3://models/fraud/v1"},
		},
		Status: securityv1alpha1.ArtifactScanStatus{
			Phase:     "Completed",
			Verdict:   securityv1alpha1.VerdictQuarantined,
			RiskScore: &risk,
			// A critical model finding is what quarantined it.
			Results: []securityv1alpha1.ScannerResult{{
				Scanner: "model-inspector", Status: "Failed", Findings: 1,
				Severities: securityv1alpha1.SeverityCounts{Critical: 1},
			}},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(digestTestScheme(t)).
		WithObjects(scan).
		WithStatusSubresource(
			&securityv1alpha1.ArtifactScan{},
			&securityv1alpha1.ModelSecurityReport{},
		).
		Build()
	r := &ArtifactScanReconciler{Client: c, Scheme: digestTestScheme(t)}
	key := client.ObjectKey{Name: "scan-quarantined", Namespace: ns}
	ctx := context.Background()

	// Without an exception the verdict must stand.
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	var before securityv1alpha1.ArtifactScan
	if err := c.Get(ctx, key, &before); err != nil {
		t.Fatal(err)
	}
	if before.Status.Verdict != securityv1alpha1.VerdictQuarantined {
		t.Fatalf("verdict changed with no exception: %s", before.Status.Verdict)
	}

	// A security engineer accepts the risk.
	if err := c.Create(ctx, &securityv1alpha1.ArtifactException{
		ObjectMeta: metav1.ObjectMeta{Name: "accept-fraud-v1", Namespace: ns},
		Spec: securityv1alpha1.ArtifactExceptionSpec{
			ModelName: "fraud", ModelVersion: "v1",
			Rules:      []string{policy.RuleBlockUnsafeModel},
			Reason:     "reviewed with the vendor; the pickle is a documented loader shim",
			ApprovedBy: "alice@corp.example",
		},
	}); err != nil {
		t.Fatal(err)
	}

	// The exception has to map back to this scan, or nothing wakes it up.
	reqs := r.mapExceptionToScans(ctx, &securityv1alpha1.ArtifactException{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns},
		Spec: securityv1alpha1.ArtifactExceptionSpec{
			ModelName: "fraud", ModelVersion: "v1",
		},
	})
	if len(reqs) != 1 || reqs[0].Name != "scan-quarantined" {
		t.Fatalf("exception mapped to %v, want the quarantined scan", reqs)
	}

	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("Reconcile after exception: %v", err)
	}

	var after securityv1alpha1.ArtifactScan
	if err := c.Get(ctx, key, &after); err != nil {
		t.Fatal(err)
	}
	if after.Status.Verdict == securityv1alpha1.VerdictQuarantined {
		t.Error("accepting the risk left the model quarantined; the button does nothing")
	}
	if !strings.Contains(after.Status.Message, "waived") {
		t.Errorf("status does not say the verdict moved because of a waiver: %q", after.Status.Message)
	}

	// The model report the gate reads has to move too, or the deployment is
	// still blocked no matter what the console shows.
	var report securityv1alpha1.ModelSecurityReport
	if err := c.Get(ctx, client.ObjectKey{Name: ModelReportName("fraud", "v1"), Namespace: ns}, &report); err != nil {
		t.Fatalf("model report was not written: %v", err)
	}
	if report.Status.Verdict == securityv1alpha1.VerdictQuarantined {
		t.Error("the model report the admission gate reads still says Quarantined")
	}
}
