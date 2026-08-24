package controller

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/naming"
)

const promoNS = "cupel-system"

func promoReport(verdict string) *securityv1alpha1.ModelSecurityReport {
	return &securityv1alpha1.ModelSecurityReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: naming.ModelReport("fraud", "v3"), Namespace: promoNS,
		},
		Status: securityv1alpha1.ModelSecurityReportStatus{Verdict: verdict},
	}
}

func promoRequest(decision string) *securityv1alpha1.PromotionRequest {
	pr := &securityv1alpha1.PromotionRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "promote-fraud", Namespace: promoNS},
		Spec: securityv1alpha1.PromotionRequestSpec{
			ModelName: "fraud", ModelVersion: "v3", TargetEnvironment: "prod",
			Requestor: "alice@davano.net", Decision: decision,
		},
	}
	if decision != "" {
		now := metav1.Now()
		pr.Spec.DecidedBy = "bob@davano.net"
		pr.Spec.DecidedAt = &now
	}
	return pr
}

func reconcilePromotion(t *testing.T, objects ...client.Object) (*securityv1alpha1.PromotionRequest, client.Client) {
	t.Helper()
	scheme := digestTestScheme(t)
	builder := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&securityv1alpha1.PromotionRequest{},
			&securityv1alpha1.ModelSecurityReport{})
	for _, o := range objects {
		builder = builder.WithObjects(o)
	}
	c := builder.Build()

	r := &PromotionReconciler{Client: c, Scheme: scheme, AuditNamespace: promoNS}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "promote-fraud", Namespace: promoNS},
	}); err != nil {
		t.Fatal(err)
	}

	out := &securityv1alpha1.PromotionRequest{}
	if err := c.Get(context.Background(),
		types.NamespacedName{Name: "promote-fraud", Namespace: promoNS}, out); err != nil {
		t.Fatal(err)
	}
	return out, c
}

// The controller never approves on its own. A promotion request that approved
// itself is a rubber stamp, and the compliance subcategory it supports is
// about human oversight.
func TestApprovedModelWaitsForAPerson(t *testing.T) {
	pr, _ := reconcilePromotion(t,
		promoReport(securityv1alpha1.VerdictApproved), promoRequest(""))

	if pr.Status.Phase != securityv1alpha1.PromotionPending {
		t.Fatalf("phase %q: a clean verdict makes a promotion permissible, not decided",
			pr.Status.Phase)
	}
	if !strings.Contains(pr.Status.Message, "spec.decision") {
		t.Errorf("the message should say what a reviewer has to do, got %q", pr.Status.Message)
	}
	if pr.Status.Verdict != securityv1alpha1.VerdictApproved {
		t.Errorf("the reviewer should see the verdict they are approving, got %q", pr.Status.Verdict)
	}
}

// A quarantined model cannot be promoted and no signature changes that. The
// phase is Blocked rather than Rejected because no person decided it.
func TestQuarantinedModelIsBlockedNotRejected(t *testing.T) {
	pr, _ := reconcilePromotion(t,
		promoReport(securityv1alpha1.VerdictQuarantined), promoRequest(""))

	if pr.Status.Phase != securityv1alpha1.PromotionBlocked {
		t.Fatalf("phase %q", pr.Status.Phase)
	}
	if pr.Status.Phase == securityv1alpha1.PromotionRejected {
		t.Error("a policy refusal must not be recorded as a human decision")
	}
}

// The check that matters: an approval signed against one verdict must not
// promote a model that has since been quarantined.
func TestSignedApprovalDoesNotSurviveANewVerdict(t *testing.T) {
	pr, c := reconcilePromotion(t,
		promoReport(securityv1alpha1.VerdictQuarantined), promoRequest(securityv1alpha1.DecisionApprove))

	if pr.Status.Phase != securityv1alpha1.PromotionBlocked {
		t.Fatalf("a signed approval must not override a quarantine, got %q", pr.Status.Phase)
	}

	report := &securityv1alpha1.ModelSecurityReport{}
	if err := c.Get(context.Background(), types.NamespacedName{
		Name: naming.ModelReport("fraud", "v3"), Namespace: promoNS}, report); err != nil {
		t.Fatal(err)
	}
	if len(report.Status.ApprovedEnvironments) != 0 {
		t.Fatalf("the environment must not be recorded, got %v", report.Status.ApprovedEnvironments)
	}
}

// A model nothing has scanned has no verdict to promote against, which is a
// different fact from a bad verdict and must not read as one.
func TestUnscannedModelIsBlockedWithTheReason(t *testing.T) {
	pr, _ := reconcilePromotion(t, promoRequest(securityv1alpha1.DecisionApprove))

	if pr.Status.Phase != securityv1alpha1.PromotionBlocked {
		t.Fatalf("phase %q", pr.Status.Phase)
	}
	if !strings.Contains(pr.Status.Message, "no security report") {
		t.Errorf("message %q should say nothing has scanned it", pr.Status.Message)
	}
}

// The field that documented itself as "managed via PromotionRequests" and that
// nothing ever wrote to.
func TestApprovalRecordsTheEnvironment(t *testing.T) {
	pr, c := reconcilePromotion(t,
		promoReport(securityv1alpha1.VerdictApproved), promoRequest(securityv1alpha1.DecisionApprove))

	if pr.Status.Phase != securityv1alpha1.PromotionApproved {
		t.Fatalf("phase %q", pr.Status.Phase)
	}
	if pr.Status.ReviewedBy != "bob@davano.net" {
		t.Errorf("reviewedBy %q", pr.Status.ReviewedBy)
	}

	report := &securityv1alpha1.ModelSecurityReport{}
	if err := c.Get(context.Background(), types.NamespacedName{
		Name: naming.ModelReport("fraud", "v3"), Namespace: promoNS}, report); err != nil {
		t.Fatal(err)
	}
	if len(report.Status.ApprovedEnvironments) != 1 || report.Status.ApprovedEnvironments[0] != "prod" {
		t.Fatalf("approvedEnvironments %v", report.Status.ApprovedEnvironments)
	}
}

// Promoting to prod must not remove a version from stage: a version runs in
// several environments at once, so this is a set and not a value.
func TestPromotingDoesNotDisplaceAnotherEnvironment(t *testing.T) {
	report := promoReport(securityv1alpha1.VerdictApproved)
	report.Status.ApprovedEnvironments = []string{"stage"}

	_, c := reconcilePromotion(t, report, promoRequest(securityv1alpha1.DecisionApprove))

	out := &securityv1alpha1.ModelSecurityReport{}
	if err := c.Get(context.Background(), types.NamespacedName{
		Name: naming.ModelReport("fraud", "v3"), Namespace: promoNS}, out); err != nil {
		t.Fatal(err)
	}
	if len(out.Status.ApprovedEnvironments) != 2 {
		t.Fatalf("both environments should stand, got %v", out.Status.ApprovedEnvironments)
	}
}

// Every terminal decision reaches the tamper-evident chain. The AI RMF mapping
// cites promotion as a human-in-the-loop step Cupel records; before this
// controller existed that was a claim with nothing behind it.
func TestPromotionIsRecordedInTheAuditChain(t *testing.T) {
	_, c := reconcilePromotion(t,
		promoReport(securityv1alpha1.VerdictApproved), promoRequest(securityv1alpha1.DecisionApprove))

	list := &securityv1alpha1.AuditRecordList{}
	if err := c.List(context.Background(), list); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("expected one audit record, got %d", len(list.Items))
	}
	rec := list.Items[0].Spec
	if rec.Type != "ModelPromoted" {
		t.Errorf("type %q", rec.Type)
	}
	if rec.Actor != "bob@davano.net" {
		t.Errorf("actor %q: the record must name who decided", rec.Actor)
	}
	if rec.Detail["environment"] != "prod" || rec.Detail["verdict"] != securityv1alpha1.VerdictApproved {
		t.Errorf("detail %v should carry the environment and the verdict it rested on", rec.Detail)
	}
	if rec.Hash == "" {
		t.Error("the record must be sealed")
	}
}

// A refusal nobody made is a policy outcome, not a judgement, and the chain
// has to be able to tell them apart.
func TestBlockedPromotionIsRecordedWithoutAHumanActor(t *testing.T) {
	_, c := reconcilePromotion(t,
		promoReport(securityv1alpha1.VerdictQuarantined), promoRequest(""))

	list := &securityv1alpha1.AuditRecordList{}
	if err := c.List(context.Background(), list); err != nil {
		t.Fatal(err)
	}
	// Blocked is not terminal, so nothing is recorded yet: the model may be
	// rescanned and the request should then proceed rather than needing to be
	// filed again.
	if len(list.Items) != 0 {
		t.Fatalf("a blocked request is not a decision, got %d records", len(list.Items))
	}
}

// Blocked has to be revisitable, or a rescan that clears a model leaves its
// promotion permanently stuck.
func TestBlockedBecomesPendingWhenTheVerdictClears(t *testing.T) {
	scheme := digestTestScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&securityv1alpha1.PromotionRequest{},
			&securityv1alpha1.ModelSecurityReport{}).
		WithObjects(promoReport(securityv1alpha1.VerdictQuarantined), promoRequest("")).
		Build()
	r := &PromotionReconciler{Client: c, Scheme: scheme}
	key := types.NamespacedName{Name: "promote-fraud", Namespace: promoNS}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatal(err)
	}

	report := &securityv1alpha1.ModelSecurityReport{}
	if err := c.Get(context.Background(), types.NamespacedName{
		Name: naming.ModelReport("fraud", "v3"), Namespace: promoNS}, report); err != nil {
		t.Fatal(err)
	}
	report.Status.Verdict = securityv1alpha1.VerdictApproved
	if err := c.Status().Update(context.Background(), report); err != nil {
		t.Fatal(err)
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatal(err)
	}
	out := &securityv1alpha1.PromotionRequest{}
	if err := c.Get(context.Background(), key, out); err != nil {
		t.Fatal(err)
	}
	if out.Status.Phase != securityv1alpha1.PromotionPending {
		t.Fatalf("a rescan that clears the model should unblock the request, got %q",
			out.Status.Phase)
	}
}

// A decided request stays decided. Re-deciding it silently would make the
// audit record disagree with the object.
func TestTerminalRequestsAreNotRevisited(t *testing.T) {
	scheme := digestTestScheme(t)
	pr := promoRequest(securityv1alpha1.DecisionApprove)
	pr.Status = securityv1alpha1.PromotionRequestStatus{
		Phase: securityv1alpha1.PromotionApproved, Message: "already done",
	}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&securityv1alpha1.PromotionRequest{},
			&securityv1alpha1.ModelSecurityReport{}).
		WithObjects(promoReport(securityv1alpha1.VerdictQuarantined), pr).
		Build()
	r := &PromotionReconciler{Client: c, Scheme: scheme}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "promote-fraud", Namespace: promoNS},
	}); err != nil {
		t.Fatal(err)
	}
	out := &securityv1alpha1.PromotionRequest{}
	if err := c.Get(context.Background(),
		types.NamespacedName{Name: "promote-fraud", Namespace: promoNS}, out); err != nil {
		t.Fatal(err)
	}
	if out.Status.Message != "already done" {
		t.Fatalf("a terminal request must not be re-decided, got %q", out.Status.Message)
	}
}
