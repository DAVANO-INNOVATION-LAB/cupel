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
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
)

// PromotionSigner stamps a promotion request with the authenticated identity
// that made it and the authenticated identity that decided it.
//
// This is the same rule ExceptionSigner enforces, for the same reason: whoever
// submits the object controls every field in it, so a requestor or a reviewer
// name in the payload is a claim about who acted, not a record of it. The
// admission request is the only place the real identity exists — by the time a
// controller reads the object, the signature is a field and no longer a fact.
//
// It also refuses the two shapes that would make the record useless later: a
// decision nobody explained, and a decision reassigned to somebody else after
// the fact.
type PromotionSigner struct {
	decoder admission.Decoder
}

// Handle implements admission.Handler.
func (p *PromotionSigner) Handle(ctx context.Context, req admission.Request) admission.Response {
	if req.Operation == admissionv1.Delete {
		return admission.Allowed("")
	}

	var pr securityv1alpha1.PromotionRequest
	if err := json.Unmarshal(req.Object.Raw, &pr); err != nil {
		return admission.Errored(http.StatusBadRequest, fmt.Errorf("decode promotion request: %w", err))
	}

	if pr.Spec.ModelName == "" || pr.Spec.ModelVersion == "" {
		return admission.Denied("spec.modelName and spec.modelVersion are required")
	}
	if pr.Spec.TargetEnvironment == "" {
		return admission.Denied("spec.targetEnvironment is required")
	}

	var old securityv1alpha1.PromotionRequest
	hasOld := req.Operation == admissionv1.Update && req.OldObject.Raw != nil
	if hasOld {
		if err := json.Unmarshal(req.OldObject.Raw, &old); err != nil {
			hasOld = false
		}
	}

	// A refusal that says nothing is indistinguishable from an oversight when
	// somebody reads it a year later and asks why the model never shipped.
	if pr.Spec.Decision == securityv1alpha1.DecisionReject &&
		strings.TrimSpace(pr.Spec.DecisionReason) == "" {
		return admission.Denied("spec.decisionReason is required to reject: a promotion " +
			"refused without a reason cannot be told from one nobody got to")
	}

	// A decision is a signature. Changing it means making a new decision, and
	// the record of the first one has to survive that.
	if hasOld && old.Spec.Decision != "" && pr.Spec.Decision != old.Spec.Decision {
		return admission.Denied(fmt.Sprintf(
			"spec.decision is the signature of %s and cannot be changed; "+
				"create a new promotion request instead",
			orUnattributedReviewer(old.Spec.DecidedBy)))
	}
	// Nor can the target move under a signed decision: approving a promotion
	// to stage and having it land in prod is the failure this whole object
	// exists to prevent.
	if hasOld && old.Spec.Decision != "" && pr.Spec.TargetEnvironment != old.Spec.TargetEnvironment {
		return admission.Denied(
			"spec.targetEnvironment cannot change once a decision is signed; " +
				"the approval was for a specific environment")
	}

	now := metav1.Now()
	signed := pr.DeepCopy()

	// Whatever the submitter wrote in these is discarded.
	if req.Operation == admissionv1.Create {
		signed.Spec.Requestor = req.UserInfo.Username
	} else {
		signed.Spec.Requestor = old.Spec.Requestor
	}

	switch {
	case signed.Spec.Decision == "":
		// Undecided: no reviewer to record, and any attempt to claim one is
		// cleared rather than trusted.
		signed.Spec.DecidedBy = ""
		signed.Spec.DecidedByGroups = nil
		signed.Spec.DecidedAt = nil
	case hasOld && old.Spec.Decision != "":
		// Already signed and unchanged; the original signature stands.
		signed.Spec.DecidedBy = old.Spec.DecidedBy
		signed.Spec.DecidedByGroups = old.Spec.DecidedByGroups
		signed.Spec.DecidedAt = old.Spec.DecidedAt
	default:
		signed.Spec.DecidedBy = req.UserInfo.Username
		signed.Spec.DecidedByGroups = req.UserInfo.Groups
		signed.Spec.DecidedAt = &now
	}

	patched, err := json.Marshal(signed)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}
	resp := admission.PatchResponseFromRaw(req.Object.Raw, patched)
	resp.Result = &metav1.Status{Message: promotionMessage(signed, req)}
	return resp
}

func promotionMessage(pr *securityv1alpha1.PromotionRequest, req admission.Request) string {
	if pr.Spec.Decision == "" {
		return fmt.Sprintf("promotion of %s %s to %s requested by %s",
			pr.Spec.ModelName, pr.Spec.ModelVersion, pr.Spec.TargetEnvironment,
			orUnattributedReviewer(pr.Spec.Requestor))
	}
	return fmt.Sprintf("promotion of %s %s to %s marked %s by %s",
		pr.Spec.ModelName, pr.Spec.ModelVersion, pr.Spec.TargetEnvironment,
		pr.Spec.Decision, orUnattributedReviewer(pr.Spec.DecidedBy))
}

func orUnattributedReviewer(who string) string {
	if who == "" {
		return "an unattributed reviewer"
	}
	return who
}

// InjectDecoder satisfies the decoder injector interface.
func (p *PromotionSigner) InjectDecoder(d admission.Decoder) error {
	p.decoder = d
	return nil
}

// SetupWithManager registers the signer.
func (p *PromotionSigner) SetupWithManager(mgr ctrl.Manager) error {
	p.decoder = admission.NewDecoder(mgr.GetScheme())
	mgr.GetWebhookServer().Register("/sign-promotion", &admission.Webhook{Handler: p})
	return nil
}
