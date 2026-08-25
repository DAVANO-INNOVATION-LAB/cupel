package controller

import (
	"context"
	"fmt"
	"path"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/compliance"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/naming"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/policy"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/scanners"
)

// ComplianceReconciler assesses each scanned model version against the
// governance frameworks declared by ComplianceProfiles in its namespace.
type ComplianceReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// AdmissionEnforcing reflects whether the gate runs in Enforce mode.
	// Revocation is only a real control when something enforces it.
	AdmissionEnforcing bool
}

// +kubebuilder:rbac:groups=security.davano.io,resources=complianceprofiles,verbs=get;list;watch
// +kubebuilder:rbac:groups=security.davano.io,resources=complianceprofiles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.davano.io,resources=compliancereports,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.davano.io,resources=compliancereports/status,verbs=get;update;patch

// Reconcile assesses one ModelSecurityReport against every matching profile.
func (r *ComplianceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var securityReport securityv1alpha1.ModelSecurityReport
	if err := r.Get(ctx, req.NamespacedName, &securityReport); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if securityReport.Status.LastScanTime == nil {
		return ctrl.Result{}, nil // not scanned yet, nothing to assess
	}

	var profiles securityv1alpha1.ComplianceProfileList
	if err := r.List(ctx, &profiles, client.InNamespace(req.Namespace)); err != nil {
		return ctrl.Result{}, fmt.Errorf("list compliance profiles: %w", err)
	}

	for i := range profiles.Items {
		profile := &profiles.Items[i]
		if !profileMatches(profile, securityReport.Spec.ModelName) {
			continue
		}
		if err := r.assess(ctx, &securityReport, profile); err != nil {
			return ctrl.Result{}, err
		}
		logger.V(1).Info("assessed model against framework",
			"model", securityReport.Spec.ModelName,
			"version", securityReport.Spec.ModelVersion,
			"framework", profile.Spec.Framework)
	}

	return ctrl.Result{}, nil
}

func (r *ComplianceReconciler) assess(ctx context.Context, securityReport *securityv1alpha1.ModelSecurityReport, profile *securityv1alpha1.ComplianceProfile) error {
	catalog, err := catalogFor(profile.Spec.Framework)
	if err != nil {
		return err
	}

	exceptions, err := r.loadExceptionsFor(ctx, securityReport)
	if err != nil {
		return err
	}

	evidence := buildEvidence(securityReport, exceptions, r.AdmissionEnforcing)
	attestations := convertAttestations(profile.Spec.Attestations)
	scope := convertScope(profile.Spec.Exclusions)

	assessment := compliance.Evaluate(catalog, evidence, attestations, scope, time.Now())

	name := naming.Stable("cr", securityReport.Spec.ModelName, securityReport.Spec.ModelVersion, profile.Name)
	report := &securityv1alpha1.ComplianceReport{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: securityReport.Namespace},
	}

	_, err = controllerutil.CreateOrUpdate(ctx, r.Client, report, func() error {
		report.Spec = securityv1alpha1.ComplianceReportSpec{
			ModelName:    securityReport.Spec.ModelName,
			ModelVersion: securityReport.Spec.ModelVersion,
			Framework:    profile.Spec.Framework,
			ProfileRef:   profile.Name,
			ReportRef:    securityReport.Name,
		}
		if report.Labels == nil {
			report.Labels = map[string]string{}
		}
		report.Labels[LabelManagedBy] = ManagerName
		report.Labels["security.davano.io/model"] = naming.SanitizeLabel(securityReport.Spec.ModelName)
		report.Labels["security.davano.io/profile"] = naming.SanitizeLabel(profile.Name)
		return controllerutil.SetControllerReference(securityReport, report, r.Scheme)
	})
	if err != nil {
		return fmt.Errorf("upsert compliance report: %w", err)
	}

	now := metav1.Now()
	report.Status = renderStatus(assessment, &now)

	condition := metav1.Condition{
		Type:    "Conformant",
		Status:  metav1.ConditionFalse,
		Reason:  "OpenControls",
		Message: assessment.Summary(),
	}
	if assessment.Conformant {
		condition.Status = metav1.ConditionTrue
		condition.Reason = "AllControlsClosed"
	}
	setCondition(&report.Status.Conditions, condition)

	if err := r.Status().Update(ctx, report); err != nil {
		return fmt.Errorf("update compliance report status: %w", err)
	}
	return r.updateProfileStatus(ctx, profile, assessment)
}

// renderStatus converts an assessment into the CRD status shape.
func renderStatus(assessment compliance.Assessment, now *metav1.Time) securityv1alpha1.ComplianceReportStatus {
	status := securityv1alpha1.ComplianceReportStatus{
		Conformant:         assessment.Conformant,
		TotalControls:      int32(assessment.Coverage.Total),
		AutomatableFull:    int32(assessment.Coverage.Full),
		AutomatablePartial: int32(assessment.Coverage.Partial),
		AttestationOnly:    int32(assessment.Coverage.None),
		OpenControlCount:   int32(len(assessment.OpenControls())),
		Message:            assessment.Summary(),
		AssessedAt:         now,
	}

	for _, characteristic := range assessment.Unmeasured {
		status.UnmeasuredCharacteristics = append(status.UnmeasuredCharacteristics, string(characteristic))
	}

	summaries := map[compliance.Function]*securityv1alpha1.FunctionSummary{}
	for _, fn := range compliance.Functions() {
		summaries[fn] = &securityv1alpha1.FunctionSummary{Function: string(fn)}
	}

	for _, result := range assessment.Results {
		entry := securityv1alpha1.ControlResult{
			ControlID:  result.Control.ID,
			Function:   string(result.Control.Function),
			Status:     string(result.Status),
			Automation: string(result.Control.Automation),
			Reason:     truncateReason(result.Reason),
			AttestedBy: result.AttestedBy,
			Warning:    result.Warning,
		}
		for _, kind := range result.EvidenceSeen {
			entry.Evidence = append(entry.Evidence, string(kind))
		}
		status.Controls = append(status.Controls, entry)

		summary := summaries[result.Control.Function]
		switch result.Status {
		case compliance.StatusSatisfied:
			summary.Satisfied++
		case compliance.StatusAttested:
			summary.Attested++
		case compliance.StatusPartiallySatisfied:
			summary.Partial++
		case compliance.StatusAttestationRequired:
			summary.AwaitingAttestation++
		case compliance.StatusNotSatisfied:
			summary.NotSatisfied++
		case compliance.StatusNotApplicable:
			summary.NotApplicable++
		}
	}

	for _, fn := range compliance.Functions() {
		status.Summary = append(status.Summary, *summaries[fn])
	}
	return status
}

func (r *ComplianceReconciler) updateProfileStatus(ctx context.Context, profile *securityv1alpha1.ComplianceProfile, assessment compliance.Assessment) error {
	now := time.Now()
	var expired int32
	for _, attestation := range profile.Spec.Attestations {
		if attestation.ExpiresAt != nil && now.After(attestation.ExpiresAt.Time) {
			expired++
		}
	}

	profile.Status.AttestedControls = int32(len(profile.Spec.Attestations))
	profile.Status.ExcludedControls = int32(len(profile.Spec.Exclusions))
	profile.Status.ExpiredAttestations = expired
	profile.Status.Message = assessment.Coverage.String()

	condition := metav1.Condition{
		Type:    "Valid",
		Status:  metav1.ConditionTrue,
		Reason:  "ProfileAccepted",
		Message: assessment.Coverage.String(),
	}
	if expired > 0 {
		condition.Status = metav1.ConditionFalse
		condition.Reason = "ExpiredAttestations"
		condition.Message = fmt.Sprintf("%d attestation(s) have expired and no longer close their control", expired)
	}
	setCondition(&profile.Status.Conditions, condition)

	if err := r.Status().Update(ctx, profile); err != nil {
		return fmt.Errorf("update compliance profile status: %w", err)
	}
	return nil
}

// buildEvidence translates a security report into framework evidence.
//
// Everything here is gated on the scan having completed. A partial scan
// evidences nothing: a scanner that never ran produced no findings, and that
// is not the same as finding nothing.
// aibomProduced reports whether a bill-of-materials scanner actually emitted a
// description of the model. A scanner that ran over an artifact it could not
// describe reports no findings and exits zero — the same shape as success —
// so the question is asked of the scanner's own answer, not of whether it ran.
func aibomProduced(results []securityv1alpha1.ScannerResult) bool {
	for _, r := range results {
		def, err := scanners.Get(r.Scanner)
		if err != nil || def.Category != scanners.CategoryAIBOM {
			continue
		}
		if r.Produced != nil && *r.Produced {
			return true
		}
	}
	return false
}

func buildEvidence(report *securityv1alpha1.ModelSecurityReport, exceptions []securityv1alpha1.ArtifactException, admissionEnforcing bool) compliance.Evidence {
	status := report.Status

	scanComplete := true
	categoriesRun := map[scanners.Category]bool{}
	for _, result := range status.Scanners {
		switch result.Status {
		case "Passed", "Failed":
			if def, err := scanners.Get(result.Scanner); err == nil {
				categoriesRun[def.Category] = true
			}
		case "Skipped":
			// Explicitly skipped is a decision, not an incomplete scan.
		default:
			scanComplete = false
		}
	}
	if len(status.Scanners) == 0 {
		scanComplete = false
	}

	return compliance.Evidence{
		ScanComplete: scanComplete,
		Verdict:      status.Verdict,
		RiskScored:   scanComplete,
		// Security and resilience needs the malware, vulnerability, and
		// model-format views together; any one alone is not the control.
		SecurityScanned: categoriesRun[scanners.CategoryMalware] &&
			categoriesRun[scanners.CategoryCVE] &&
			categoriesRun[scanners.CategoryModel],
		SecretsScanned: categoriesRun[scanners.CategorySecret],
		SBOMGenerated:  status.SBOMRef != "" || categoriesRun[scanners.CategorySBOM],
		// Deliberately not "the scanner ran". A bill-of-materials scanner
		// that examined an artifact it could not describe produces no
		// document and no findings, and treating that as evidence would let
		// a control be satisfied by an absence.
		AIBOMGenerated:    aibomProduced(status.Scanners),
		SignatureVerified: status.SignatureVerified,
		PolicyRef:         report.Spec.ScanRef,
		Inventoried:       status.LastScanTime != nil,
		// A scan that repeats is what makes monitoring continuous; a single
		// scan at registration is a point-in-time check.
		ContinuousMonitoring:    status.LastScanTime != nil,
		AdmissionEnforcing:      admissionEnforcing,
		ResidualRisksDocumented: residualRisksDocumented(exceptions),
		// Fairness testing is not an artifact scan, so this is never set from
		// one. MEASURE 2.11 takes its own evidence or an attestation.
		BiasEvaluated: false,
	}
}

// residualRisksDocumented reports whether every accepted risk carries a
// reason and an approver. An undocumented waiver is an undocumented residual
// risk, which is exactly what MANAGE 1.4 is about.
func residualRisksDocumented(exceptions []securityv1alpha1.ArtifactException) bool {
	for _, exception := range exceptions {
		if exception.Spec.Reason == "" || exception.Spec.ApprovedBy == "" {
			return false
		}
	}
	return true
}

func (r *ComplianceReconciler) loadExceptionsFor(ctx context.Context, report *securityv1alpha1.ModelSecurityReport) ([]securityv1alpha1.ArtifactException, error) {
	var list securityv1alpha1.ArtifactExceptionList
	if err := r.List(ctx, &list, client.InNamespace(report.Namespace)); err != nil {
		return nil, fmt.Errorf("list exceptions: %w", err)
	}
	return policy.ExceptionsFor(list.Items, report.Spec.ModelName, report.Spec.ModelVersion), nil
}

func catalogFor(framework string) (*compliance.Catalog, error) {
	switch compliance.Framework(framework) {
	case compliance.NISTAIRMF10, "":
		return compliance.NISTAIRMF(), nil
	default:
		return nil, fmt.Errorf("unsupported compliance framework %q", framework)
	}
}

func convertAttestations(in []securityv1alpha1.ControlAttestation) []compliance.Attestation {
	out := make([]compliance.Attestation, 0, len(in))
	for _, a := range in {
		converted := compliance.Attestation{
			ControlID:   a.ControlID,
			Statement:   a.Statement,
			AttestedBy:  a.AttestedBy,
			EvidenceURI: a.EvidenceURI,
		}
		if a.AttestedAt != nil {
			converted.AttestedAt = a.AttestedAt.Time
		}
		if a.ExpiresAt != nil {
			converted.ExpiresAt = a.ExpiresAt.Time
		}
		out = append(out, converted)
	}
	return out
}

func convertScope(exclusions []securityv1alpha1.ControlExclusion) compliance.Scope {
	scope := compliance.Scope{NotApplicable: map[string]string{}}
	for _, exclusion := range exclusions {
		scope.NotApplicable[exclusion.ControlID] = exclusion.Justification
	}
	return scope
}

func profileMatches(profile *securityv1alpha1.ComplianceProfile, modelName string) bool {
	if len(profile.Spec.ModelSelector) == 0 {
		return true
	}
	for _, pattern := range profile.Spec.ModelSelector {
		if ok, err := path.Match(pattern, modelName); err == nil && ok {
			return true
		}
	}
	return false
}

// maxReasonLength keeps a 72-control report inside etcd's object size limit.
const maxReasonLength = 400

func truncateReason(reason string) string {
	if len(reason) <= maxReasonLength {
		return reason
	}
	return reason[:maxReasonLength] + "..."
}

// SetupWithManager wires the reconciler into the manager.
func (r *ComplianceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.ModelSecurityReport{}).
		Owns(&securityv1alpha1.ComplianceReport{}).
		Named("compliance").
		Complete(r)
}
