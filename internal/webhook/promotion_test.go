package webhook

import (
	"context"
	"encoding/json"

	jsonpatch "github.com/evanphx/json-patch/v5"
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
)

func promotionReq(t *testing.T, pr securityv1alpha1.PromotionRequest, user string, old *securityv1alpha1.PromotionRequest) admission.Request {
	t.Helper()
	raw, err := json.Marshal(pr)
	if err != nil {
		t.Fatal(err)
	}
	req := admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		Operation: admissionv1.Create,
		Namespace: testNamespace,
		Object:    runtime.RawExtension{Raw: raw},
		UserInfo:  authenticationv1.UserInfo{Username: user, Groups: []string{"reviewers"}},
	}}
	if old != nil {
		oldRaw, err := json.Marshal(*old)
		if err != nil {
			t.Fatal(err)
		}
		req.Operation = admissionv1.Update
		req.OldObject = runtime.RawExtension{Raw: oldRaw}
	}
	return req
}

func applyPromotion(t *testing.T, resp admission.Response, base securityv1alpha1.PromotionRequest) securityv1alpha1.PromotionRequest {
	t.Helper()
	if !resp.Allowed {
		t.Fatalf("denied: %v", resp.Result)
	}
	raw, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	patchRaw, err := json.Marshal(resp.Patches)
	if err != nil {
		t.Fatal(err)
	}
	patch, err := jsonpatch.DecodePatch(patchRaw)
	if err != nil {
		t.Fatalf("decode admission patch: %v", err)
	}
	patched, err := patch.Apply(raw)
	if err != nil {
		t.Fatalf("apply admission patch: %v", err)
	}
	var out securityv1alpha1.PromotionRequest
	if err := json.Unmarshal(patched, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func basePromotion() securityv1alpha1.PromotionRequest {
	return securityv1alpha1.PromotionRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: testNamespace},
		Spec: securityv1alpha1.PromotionRequestSpec{
			ModelName: "fraud", ModelVersion: "v3", TargetEnvironment: "prod",
		},
	}
}

// The rule the whole object depends on: whoever submits it controls every
// field, so a requestor in the payload is a claim rather than a record.
func TestRequestorIsTakenFromTheAuthenticatedIdentity(t *testing.T) {
	pr := basePromotion()
	pr.Spec.Requestor = "someone-else@example.com"

	signer := &PromotionSigner{}
	out := applyPromotion(t, signer.Handle(context.Background(),
		promotionReq(t, pr, "alice@davano.net", nil)), pr)

	if out.Spec.Requestor != "alice@davano.net" {
		t.Fatalf("requestor %q: the submitted value must be discarded", out.Spec.Requestor)
	}
}

func TestReviewerIsStampedWhenTheDecisionIsMade(t *testing.T) {
	old := basePromotion()
	pr := basePromotion()
	pr.Spec.Decision = securityv1alpha1.DecisionApprove
	pr.Spec.DecidedBy = "not-me@example.com"

	signer := &PromotionSigner{}
	out := applyPromotion(t, signer.Handle(context.Background(),
		promotionReq(t, pr, "bob@davano.net", &old)), pr)

	if out.Spec.DecidedBy != "bob@davano.net" {
		t.Fatalf("decidedBy %q", out.Spec.DecidedBy)
	}
	if out.Spec.DecidedAt == nil {
		t.Error("the decision must be timestamped")
	}
	if len(out.Spec.DecidedByGroups) == 0 {
		t.Error("the reviewer's groups are what an authorization review reads")
	}
}

// A claim of having decided, on an object with no decision, is cleared rather
// than trusted.
func TestUndecidedRequestCarriesNoReviewer(t *testing.T) {
	pr := basePromotion()
	pr.Spec.DecidedBy = "phantom@example.com"
	now := metav1.Now()
	pr.Spec.DecidedAt = &now

	signer := &PromotionSigner{}
	out := applyPromotion(t, signer.Handle(context.Background(),
		promotionReq(t, pr, "alice@davano.net", nil)), pr)

	if out.Spec.DecidedBy != "" || out.Spec.DecidedAt != nil {
		t.Fatalf("an undecided request must carry no reviewer, got %q / %v",
			out.Spec.DecidedBy, out.Spec.DecidedAt)
	}
}

// A refusal that says nothing cannot be told from a request nobody got to.
func TestRejectionNeedsAReason(t *testing.T) {
	old := basePromotion()
	pr := basePromotion()
	pr.Spec.Decision = securityv1alpha1.DecisionReject

	signer := &PromotionSigner{}
	resp := signer.Handle(context.Background(), promotionReq(t, pr, "bob@davano.net", &old))
	if resp.Allowed {
		t.Fatal("a rejection with no reason must be refused")
	}
}

// A decision is a signature. Changing it means making a new decision, and the
// first one has to survive that.
func TestSignedDecisionCannotBeChanged(t *testing.T) {
	now := metav1.Now()
	old := basePromotion()
	old.Spec.Decision = securityv1alpha1.DecisionReject
	old.Spec.DecisionReason = "waiting on the pen test"
	old.Spec.DecidedBy = "bob@davano.net"
	old.Spec.DecidedAt = &now

	pr := basePromotion()
	pr.Spec.Decision = securityv1alpha1.DecisionApprove

	signer := &PromotionSigner{}
	resp := signer.Handle(context.Background(), promotionReq(t, pr, "mallory@davano.net", &old))
	if resp.Allowed {
		t.Fatal("a signed decision must not be reassignable")
	}
	if !strings.Contains(resp.Result.Message, "bob@davano.net") {
		t.Errorf("the denial should name the original signer, got %q", resp.Result.Message)
	}
}

// Approving a promotion to stage and having it land in prod is the failure the
// object exists to prevent.
func TestTargetEnvironmentCannotMoveUnderASignedDecision(t *testing.T) {
	now := metav1.Now()
	old := basePromotion()
	old.Spec.Decision = securityv1alpha1.DecisionApprove
	old.Spec.TargetEnvironment = "stage"
	old.Spec.DecidedBy = "bob@davano.net"
	old.Spec.DecidedAt = &now

	pr := basePromotion()
	pr.Spec.Decision = securityv1alpha1.DecisionApprove
	pr.Spec.TargetEnvironment = "prod"

	signer := &PromotionSigner{}
	if signer.Handle(context.Background(), promotionReq(t, pr, "bob@davano.net", &old)).Allowed {
		t.Fatal("the environment an approval was signed for must be fixed")
	}
}

// The original signature stands across unrelated edits, so amending a
// justification does not re-date somebody else's approval.
func TestUnchangedDecisionKeepsItsOriginalSignature(t *testing.T) {
	// Truncated to the second, because that is the precision metav1.Time
	// serialises at — comparing an untruncated value across a JSON round trip
	// tests the encoding, not the signer.
	then := metav1.NewTime(time.Now().Add(-48 * time.Hour)).Rfc3339Copy()
	old := basePromotion()
	old.Spec.Decision = securityv1alpha1.DecisionApprove
	old.Spec.DecidedBy = "bob@davano.net"
	old.Spec.DecidedAt = &then
	old.Spec.Requestor = "alice@davano.net"

	pr := old
	pr.Spec.Justification = "amended after review"

	signer := &PromotionSigner{}
	out := applyPromotion(t, signer.Handle(context.Background(),
		promotionReq(t, pr, "mallory@davano.net", &old)), pr)

	if out.Spec.DecidedBy != "bob@davano.net" {
		t.Fatalf("decidedBy %q", out.Spec.DecidedBy)
	}
	if !out.Spec.DecidedAt.Equal(&then) {
		t.Error("an unrelated edit must not re-date the approval")
	}
	if out.Spec.Requestor != "alice@davano.net" {
		t.Errorf("requestor %q: an update must not reassign who asked", out.Spec.Requestor)
	}
}
