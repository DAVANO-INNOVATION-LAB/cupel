package controller

import (
	"context"
	"fmt"
	"sort"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/audit"
)

// PromotionReconciler drives PromotionRequests.
//
// The type had a CRD, a status with an approval workflow, and no controller —
// a published API nothing acted on. Worse, the AI RMF mapping cited promotion
// as a human-in-the-loop step "Cupel records with an approver", which was a
// claim of coverage with nothing behind it. This is the code that makes that
// sentence true.
//
// The division of labour is the whole design:
//
//   - The controller decides what is *permissible*. A model whose security
//     verdict is not Approved cannot be promoted, and no signature changes
//     that. That outcome is Blocked, which is deliberately a different phase
//     from Rejected: one is a policy refusal, the other is a person's
//     judgement, and collapsing them would let a machine's decision be read
//     as a human's.
//   - A person decides whether it *should* happen. The controller never
//     auto-approves. A promotion request that approved itself would be a
//     rubber stamp, and the compliance claim it exists to support is about
//     human oversight.
//
// The check that matters most runs at approval time, not at request time. An
// approval signed on Tuesday must not promote a model that was quarantined on
// Wednesday, so the verdict is re-read when the decision is acted on and the
// verdict it was evaluated against is recorded in the status.
type PromotionReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// AuditNamespace is where the tamper-evident chain lives. Empty disables
	// recording; promotions still work, and the chain having stopped is
	// visible because the operator logs it.
	AuditNamespace string
}

// +kubebuilder:rbac:groups=security.davano.io,resources=promotionrequests,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security.davano.io,resources=promotionrequests/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.davano.io,resources=modelsecurityreports,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security.davano.io,resources=modelsecurityreports/status,verbs=get;update;patch

// Reconcile evaluates one promotion request.
func (r *PromotionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	pr := &securityv1alpha1.PromotionRequest{}
	if err := r.Get(ctx, req.NamespacedName, pr); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// A request that already reached a terminal state stays there. Re-deciding
	// an approved promotion silently would make the audit record a lie about
	// what the object says now.
	if isTerminal(pr.Status.Phase) {
		return ctrl.Result{}, nil
	}

	report, err := r.securityReport(ctx, pr)
	if err != nil {
		return ctrl.Result{}, err
	}

	next := pr.Status.DeepCopy()
	next.Verdict = verdictOf(report)
	next.ObservedVerdictTime = verdictTimeOf(report)

	switch {
	case report == nil:
		next.Phase = securityv1alpha1.PromotionBlocked
		next.Message = fmt.Sprintf(
			"model %q version %q has no security report; nothing has scanned it, "+
				"so there is no verdict to promote against",
			pr.Spec.ModelName, pr.Spec.ModelVersion)

	case report.Status.Verdict != securityv1alpha1.VerdictApproved:
		// Blocked rather than Rejected: no person declined this.
		next.Phase = securityv1alpha1.PromotionBlocked
		next.Message = fmt.Sprintf(
			"the security verdict for %s %s is %q; a promotion cannot override a verdict",
			pr.Spec.ModelName, pr.Spec.ModelVersion, orUnknownVerdict(report.Status.Verdict))

	case pr.Spec.Decision == securityv1alpha1.DecisionReject:
		next.Phase = securityv1alpha1.PromotionRejected
		next.ReviewedBy = pr.Spec.DecidedBy
		next.ReviewTime = pr.Spec.DecidedAt
		next.Message = declineMessage(pr)

	case pr.Spec.Decision == securityv1alpha1.DecisionApprove:
		next.Phase = securityv1alpha1.PromotionApproved
		next.ReviewedBy = pr.Spec.DecidedBy
		next.ReviewTime = pr.Spec.DecidedAt
		next.Message = fmt.Sprintf("promoted to %s by %s",
			pr.Spec.TargetEnvironment, orUnattributed(pr.Spec.DecidedBy))
		if err := r.applyEnvironment(ctx, report, pr.Spec.TargetEnvironment); err != nil {
			return ctrl.Result{}, err
		}

	default:
		// Permissible, and waiting on a person.
		next.Phase = securityv1alpha1.PromotionPending
		next.Message = fmt.Sprintf(
			"the security verdict is Approved; set spec.decision to Approve or Reject to promote %s to %s",
			pr.Spec.ModelVersion, pr.Spec.TargetEnvironment)
	}

	if statusUnchanged(pr.Status, *next) {
		return ctrl.Result{}, nil
	}

	previous := pr.Status.Phase
	pr.Status = *next
	if err := r.Status().Update(ctx, pr); err != nil {
		return ctrl.Result{}, err
	}

	if isTerminal(next.Phase) && !isTerminal(previous) {
		r.record(ctx, pr)
		logger.Info("promotion decided", "model", pr.Spec.ModelName,
			"version", pr.Spec.ModelVersion, "environment", pr.Spec.TargetEnvironment,
			"phase", next.Phase, "decidedBy", pr.Spec.DecidedBy)
	}
	return ctrl.Result{}, nil
}

// securityReport finds the verdict this promotion would rest on. A missing
// report is not an error: it is the answer, and the caller reports it as one.
func (r *PromotionReconciler) securityReport(ctx context.Context, pr *securityv1alpha1.PromotionRequest) (*securityv1alpha1.ModelSecurityReport, error) {
	// Current name first, then the name a report would have been written under
	// before names carried a fingerprint. A report found either way still has
	// to be about the model the request names.
	for _, name := range ModelReportNames(pr.Spec.ModelName, pr.Spec.ModelVersion) {
		report := &securityv1alpha1.ModelSecurityReport{}
		key := client.ObjectKey{Name: name, Namespace: pr.Namespace}
		err := r.Get(ctx, key, report)
		switch {
		case apierrors.IsNotFound(err):
			continue
		case err != nil:
			return nil, err
		}
		if report.Spec.ModelName != "" && report.Spec.ModelName != pr.Spec.ModelName {
			continue
		}
		if report.Spec.ModelVersion != "" && pr.Spec.ModelVersion != "" &&
			report.Spec.ModelVersion != pr.Spec.ModelVersion {
			continue
		}
		return report, nil
	}
	return nil, nil
}

// applyEnvironment records where an approved model version now runs.
//
// ApprovedEnvironments documented itself as "managed via PromotionRequests"
// and nothing ever wrote to it. It is a set rather than a single value because
// a version legitimately runs in several environments at once, and promoting
// to prod must not quietly remove it from stage.
func (r *PromotionReconciler) applyEnvironment(ctx context.Context, report *securityv1alpha1.ModelSecurityReport, environment string) error {
	for _, existing := range report.Status.ApprovedEnvironments {
		if existing == environment {
			return nil
		}
	}
	report.Status.ApprovedEnvironments = append(report.Status.ApprovedEnvironments, environment)
	sort.Strings(report.Status.ApprovedEnvironments)
	return r.Status().Update(ctx, report)
}

func (r *PromotionReconciler) record(ctx context.Context, pr *securityv1alpha1.PromotionRequest) {
	if r.AuditNamespace == "" {
		return
	}
	recorder := &audit.Recorder{Client: r.Client, Namespace: r.AuditNamespace}
	rec := audit.PromotionDecision(
		pr.Spec.ModelName, pr.Spec.ModelVersion, pr.Spec.TargetEnvironment,
		pr.Status.Phase, pr.Spec.DecidedBy, pr.Status.Verdict, pr.Status.Message)
	if pr.Spec.Requestor != "" {
		rec.Detail["requestor"] = pr.Spec.Requestor
	}
	if pr.Spec.Justification != "" {
		rec.Detail["justification"] = pr.Spec.Justification
	}
	if _, err := recorder.Append(ctx, rec); err != nil {
		// As everywhere else, a failed chain write does not undo the decision.
		log.FromContext(ctx).Error(err, "could not record promotion in the audit chain",
			"model", pr.Spec.ModelName, "phase", pr.Status.Phase)
	}
}

func isTerminal(phase string) bool {
	switch phase {
	case securityv1alpha1.PromotionApproved, securityv1alpha1.PromotionRejected:
		return true
	}
	// Blocked is deliberately not terminal: a model that gets rescanned and
	// approved should let its pending promotion proceed rather than forcing
	// somebody to file the request again.
	return false
}

func statusUnchanged(a, b securityv1alpha1.PromotionRequestStatus) bool {
	return a.Phase == b.Phase && a.Message == b.Message &&
		a.Verdict == b.Verdict && a.ReviewedBy == b.ReviewedBy &&
		timeEqual(a.ReviewTime, b.ReviewTime) &&
		timeEqual(a.ObservedVerdictTime, b.ObservedVerdictTime)
}

func timeEqual(a, b *metav1.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(b)
}

func verdictOf(report *securityv1alpha1.ModelSecurityReport) string {
	if report == nil {
		return ""
	}
	return report.Status.Verdict
}

func verdictTimeOf(report *securityv1alpha1.ModelSecurityReport) *metav1.Time {
	if report == nil {
		return nil
	}
	return report.Status.LastScanTime
}

func orUnknownVerdict(v string) string {
	if v == "" {
		return "not yet decided"
	}
	return v
}

func orUnattributed(who string) string {
	if who == "" {
		return "an unattributed reviewer"
	}
	return who
}

func declineMessage(pr *securityv1alpha1.PromotionRequest) string {
	if pr.Spec.DecisionReason != "" {
		return fmt.Sprintf("declined by %s: %s",
			orUnattributed(pr.Spec.DecidedBy), pr.Spec.DecisionReason)
	}
	return fmt.Sprintf("declined by %s", orUnattributed(pr.Spec.DecidedBy))
}

// SetupWithManager wires the reconciler into the manager.
func (r *PromotionReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.PromotionRequest{}).
		Complete(r)
}
