package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/audit"
)

// ExceptionSigner stamps an ArtifactException with the authenticated identity
// of whoever created it.
//
// A waiver is the one place in Cupel where a human overrides the machine, so
// it is the one record that has to survive an argument a year later: who
// accepted this risk, when, on what grounds, and against which bytes. A
// free-text "approvedBy" field cannot answer that — anyone who can create the
// object can type anyone's name into it.
//
// The API server has already authenticated the request, so the webhook takes
// the identity from there and overwrites whatever was submitted. That makes
// the attribution a property of the request rather than a claim in its body.
type ExceptionSigner struct {
	decoder admission.Decoder
	// Recorder appends accepted risks to the tamper-evident decision log.
	// Nil disables recording; the webhook still signs, because refusing an
	// acceptance because the audit write failed would leave the reviewer
	// unable to act at all.
	Recorder *audit.Recorder
}

// Handle implements admission.Handler.
func (e *ExceptionSigner) Handle(ctx context.Context, req admission.Request) admission.Response {
	if req.Operation == admissionv1.Delete {
		return admission.Allowed("")
	}

	var ex securityv1alpha1.ArtifactException
	if err := json.Unmarshal(req.Object.Raw, &ex); err != nil {
		return admission.Errored(http.StatusBadRequest, fmt.Errorf("decode exception: %w", err))
	}

	// An unexplained waiver is indistinguishable from a mistake later.
	if strings.TrimSpace(ex.Spec.Reason) == "" {
		return admission.Denied("spec.reason is required: an accepted risk has to say why it was accepted")
	}
	if ex.Spec.ModelName == "" || ex.Spec.ModelVersion == "" {
		return admission.Denied("spec.modelName and spec.modelVersion are required")
	}
	if len(ex.Spec.Rules) == 0 && len(ex.Spec.FindingIDs) == 0 {
		return admission.Denied("an exception must waive something: set spec.rules or spec.findingIDs")
	}

	// On update, the original signature stands. Re-approving means creating a
	// new exception, so the history is append-only rather than editable.
	if req.Operation == admissionv1.Update && req.OldObject.Raw != nil {
		var old securityv1alpha1.ArtifactException
		if err := json.Unmarshal(req.OldObject.Raw, &old); err == nil && old.Spec.ApprovedBy != "" {
			if ex.Spec.ApprovedBy != old.Spec.ApprovedBy {
				return admission.Denied(fmt.Sprintf(
					"spec.approvedBy is the signature of %q and cannot be reassigned; create a new exception instead",
					old.Spec.ApprovedBy))
			}
			// Widening what a signed waiver covers is a new decision, not an
			// edit to an old one.
			if !subset(ex.Spec.Rules, old.Spec.Rules) || !subset(ex.Spec.FindingIDs, old.Spec.FindingIDs) {
				return admission.Denied(
					"a signed exception cannot be widened; create a new exception so the approval is attributable")
			}
		}
	}

	now := metav1.Now()
	signed := ex.DeepCopy()
	// Whatever the submitter put here is discarded. This is the whole point:
	// the identity comes from the authenticated request, not the payload.
	signed.Spec.ApprovedBy = req.UserInfo.Username
	signed.Spec.ApprovedByGroups = req.UserInfo.Groups
	if signed.Spec.ApprovedAt == nil || req.Operation == admissionv1.Create {
		signed.Spec.ApprovedAt = &now
	}

	// An accepted risk is the decision an audit most wants to see: a human
	// overriding a policy that would otherwise have blocked something. It is
	// recorded here rather than in a controller because this is the only place
	// the authenticated identity exists — by the time the object is stored,
	// the signature is a field and no longer a fact about the request.
	e.record(ctx, signed, req.Operation)

	patched, err := json.Marshal(signed)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}
	resp := admission.PatchResponseFromRaw(req.Object.Raw, patched)
	resp.Result = &metav1.Status{
		Message: fmt.Sprintf("risk accepted for %s %s by %s",
			ex.Spec.ModelName, ex.Spec.ModelVersion, req.UserInfo.Username),
	}
	return resp
}

// subset reports whether every element of a is present in b.
func subset(a, b []string) bool {
	have := make(map[string]bool, len(b))
	for _, x := range b {
		have[x] = true
	}
	for _, x := range a {
		if !have[x] {
			return false
		}
	}
	return true
}

// SetupWithManager registers the signer.
func (e *ExceptionSigner) SetupWithManager(mgr ctrl.Manager) error {
	e.decoder = admission.NewDecoder(mgr.GetScheme())
	mgr.GetWebhookServer().Register("/sign-exception", &admission.Webhook{Handler: e})
	return nil
}

// record appends the acceptance to the audit chain.
//
// Best-effort by design. A failed audit write must not stop a reviewer from
// accepting a risk: the acceptance is still attributable through the object
// itself, and a gap in the chain is detectable, whereas a reviewer blocked
// from recording a decision produces no record anywhere.
func (e *ExceptionSigner) record(ctx context.Context, ex *securityv1alpha1.ArtifactException, op admissionv1.Operation) {
	if e.Recorder == nil || op != admissionv1.Create {
		return
	}
	rec := audit.RiskAccepted(
		ex.Spec.ModelName, ex.Spec.ModelVersion,
		ex.Spec.ApprovedBy, ex.Spec.Reason,
		append(append([]string{}, ex.Spec.FindingIDs...), ex.Spec.Rules...),
		ex.Spec.ScannedDigest,
	)
	if _, err := e.Recorder.Append(ctx, rec); err != nil {
		log.FromContext(ctx).Error(err, "could not record the accepted risk in the audit log",
			"model", ex.Spec.ModelName, "approvedBy", ex.Spec.ApprovedBy)
	}
}
