package controller

import (
	"context"
	"fmt"
	"slices"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/audit"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/metrics"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/policy"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/scanners"
)

// ArtifactScanReconciler drives one ArtifactScan through fetch, scan, and
// verdict. It owns the scan Jobs and the resulting ModelSecurityReport.
type ArtifactScanReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	JobConfig JobConfig
	// ScanDeadline bounds how long a scan may stay unfinished before it is
	// failed. Zero uses DefaultScanDeadline.
	ScanDeadline time.Duration
	// TrustRootPath is a Sigstore trusted-root JSON file mounted into the
	// operator. Empty means signature verification cannot chain certificates,
	// which the provenance scanner reports rather than working around by
	// fetching a root over the network — an air-gapped cluster cannot.
	TrustRootPath string
	// RequireTransparencyLog demands an auditable log entry, not just a valid
	// signature.
	RequireTransparencyLog bool
	// AuditNamespace is where the tamper-evident decision log is written.
	// Empty disables recording, which also means the AU-9 control claim in
	// internal/compliance has nothing behind it — so it is reported rather
	// than silently skipped.
	AuditNamespace string
}

// +kubebuilder:rbac:groups=security.davano.io,resources=artifactscans,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.davano.io,resources=artifactscans/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.davano.io,resources=artifactscanreports,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.davano.io,resources=artifactscanpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=security.davano.io,resources=artifactexceptions,verbs=get;list;watch
// +kubebuilder:rbac:groups=security.davano.io,resources=modelsecurityreports,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=security.davano.io,resources=modelsecurityreports/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.davano.io,resources=trustedpublishers,verbs=get;list;watch
// +kubebuilder:rbac:groups=security.davano.io,resources=auditrecords,verbs=get;list;watch;create
// +kubebuilder:rbac:groups=security.davano.io,resources=auditcheckpoints,verbs=get;list;watch;create;update
// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch;create;delete
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile implements the ArtifactScan state machine.
func (r *ArtifactScanReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var scan securityv1alpha1.ArtifactScan
	if err := r.Get(ctx, req.NamespacedName, &scan); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !scan.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	if scan.Status.Phase == "" {
		scan.Status.Phase = "Pending"
		now := metav1.Now()
		scan.Status.StartTime = &now
		if err := r.Status().Update(ctx, &scan); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// A finished scan is not immutable. Accepting a risk creates an
	// ArtifactException, and if a terminal phase simply returned here, that
	// acceptance would change nothing: the verdict would stay Quarantined
	// forever and the button that recorded it would look broken, because it
	// would be. Re-evaluating is cheap — the policy engine is pure, the scan
	// results are already on the object — so a finished scan re-derives its
	// verdict against the exceptions that exist now.
	if scan.Status.Phase == "Completed" || scan.Status.Phase == "Failed" {
		return r.reevaluate(ctx, &scan)
	}

	pol, err := r.loadPolicy(ctx, &scan)
	if err != nil {
		return ctrl.Result{}, err
	}

	wanted, err := resolveScanners(&scan, pol)
	if err != nil {
		return r.fail(ctx, &scan, fmt.Sprintf("cannot resolve scanner set: %v", err))
	}
	if len(wanted) == 0 {
		return r.fail(ctx, &scan, "policy selected no scanners")
	}

	// Refresh the rendered trust policy before any Job mounts it. Doing this
	// after Job creation would let a provenance scan verify against a stale
	// publisher set — including one a revoked publisher is still in.
	if slices.Contains(wanted, "provenance") {
		if err := SyncTrustPolicy(ctx, r.Client, scan.Namespace, r.TrustRootPath, r.RequireTransparencyLog); err != nil {
			logger.Error(err, "could not render the trust policy", "scan", scan.Name)
		}
	}

	// Ensure a Job exists for every selected scanner.
	for _, name := range wanted {
		if err := r.ensureScanJob(ctx, &scan, pol, name); err != nil {
			return ctrl.Result{}, err
		}
	}

	if scan.Status.Phase == "Pending" {
		scan.Status.Phase = "Scanning"
		if err := r.Status().Update(ctx, &scan); err != nil {
			return ctrl.Result{}, err
		}
	}

	results, pending, err := r.collectResults(ctx, &scan, wanted)
	if err != nil {
		return ctrl.Result{}, err
	}

	scan.Status.Results = results
	if pending > 0 {
		// A scan can wait forever on a report that will never arrive: the Job
		// succeeds, its TTL deletes it, and the publish step never wrote the
		// report (OOM, RBAC denial, API conflict). From then on there is no Job
		// to read a status from and no report to read a result from, so the
		// scan requeues every 15s indefinitely, with the evidence already
		// garbage-collected. A deadline converts that silent hang into a
		// verdict an operator can see and a policy can act on.
		if deadline := r.scanDeadline(); deadline > 0 && scan.Status.StartTime != nil {
			if waited := time.Since(scan.Status.StartTime.Time); waited > deadline {
				return r.fail(ctx, &scan, fmt.Sprintf(
					"scan did not complete within %s (%d scanner(s) still pending); "+
						"check the scan job logs and the publish step's RBAC",
					deadline, pending))
			}
		}
		logger.V(1).Info("waiting on scanners", "pending", pending, "scan", scan.Name)
		if err := r.Status().Update(ctx, &scan); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: 15 * time.Second}, nil
	}

	exceptions, err := r.loadExceptions(ctx, &scan)
	if err != nil {
		return ctrl.Result{}, err
	}

	eval := policy.Evaluate(results, scan.Spec.Artifact, pol, exceptions, time.Now())

	now := metav1.Now()
	scan.Status.Phase = "Completed"
	scan.Status.CompletionTime = &now
	scan.Status.RiskScore = &eval.RiskScore
	scan.Status.Verdict = eval.Verdict
	scan.Status.Message = summarize(eval)
	setCondition(&scan.Status.Conditions, metav1.Condition{
		Type:    "Complete",
		Status:  metav1.ConditionTrue,
		Reason:  "ScanFinished",
		Message: scan.Status.Message,
	})
	if err := r.Status().Update(ctx, &scan); err != nil {
		return ctrl.Result{}, err
	}

	// A verdict is a decision, and the decisions are what an audit asks about.
	// Recording is best-effort on purpose: losing the audit entry must not
	// also lose the verdict, and a chain with a gap is detectable while a
	// scan that failed to complete is not.
	r.recordVerdict(ctx, &scan, eval)

	if err := r.upsertModelSecurityReport(ctx, &scan, eval); err != nil {
		return ctrl.Result{}, err
	}

	metrics.ScanVerdicts.WithLabelValues(eval.Verdict).Inc()
	for _, result := range results {
		metrics.ScannerResults.WithLabelValues(result.Scanner, result.Status).Inc()
	}
	if scan.Status.StartTime != nil {
		metrics.ScanDuration.Observe(now.Sub(scan.Status.StartTime.Time).Seconds())
	}

	logger.Info("scan completed",
		"scan", scan.Name, "verdict", eval.Verdict, "risk", eval.RiskScore,
		"violations", len(eval.Violations))
	return ctrl.Result{}, nil
}

// reevaluate re-derives the verdict of an already-finished scan against the
// exceptions and policy in force now. It writes only when something actually
// changed, so a steady-state reconcile is a no-op rather than a write loop.
func (r *ArtifactScanReconciler) reevaluate(ctx context.Context, scan *securityv1alpha1.ArtifactScan) (ctrl.Result, error) {
	if len(scan.Status.Results) == 0 {
		return ctrl.Result{}, nil
	}
	pol, err := r.loadPolicy(ctx, scan)
	if err != nil {
		return ctrl.Result{}, err
	}
	exceptions, err := r.loadExceptions(ctx, scan)
	if err != nil {
		return ctrl.Result{}, err
	}

	eval := policy.Evaluate(scan.Status.Results, scan.Spec.Artifact, pol, exceptions, time.Now())
	if eval.Verdict == scan.Status.Verdict &&
		scan.Status.RiskScore != nil && *scan.Status.RiskScore == eval.RiskScore {
		return ctrl.Result{}, nil
	}

	previous := scan.Status.Verdict
	scan.Status.Verdict = eval.Verdict
	scan.Status.RiskScore = &eval.RiskScore
	scan.Status.Message = summarize(eval)
	if len(eval.Waived) > 0 {
		// Say plainly that the verdict moved because a human accepted the
		// risk, not because the artifact changed.
		scan.Status.Message = fmt.Sprintf("%s (%d violation(s) waived by exception)",
			scan.Status.Message, len(eval.Waived))
	}
	if err := r.Status().Update(ctx, scan); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.upsertModelSecurityReport(ctx, scan, eval); err != nil {
		return ctrl.Result{}, err
	}
	log.FromContext(ctx).Info("verdict re-evaluated after an exception changed",
		"scan", scan.Name, "from", previous, "to", eval.Verdict, "waived", len(eval.Waived))
	metrics.ScanVerdicts.WithLabelValues(eval.Verdict).Inc()
	return ctrl.Result{}, nil
}

func (r *ArtifactScanReconciler) loadPolicy(ctx context.Context, scan *securityv1alpha1.ArtifactScan) (*securityv1alpha1.ArtifactScanPolicy, error) {
	if scan.Spec.PolicyRef == "" {
		return nil, nil
	}
	var pol securityv1alpha1.ArtifactScanPolicy
	err := r.Get(ctx, client.ObjectKey{Name: scan.Spec.PolicyRef, Namespace: scan.Namespace}, &pol)
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load policy %q: %w", scan.Spec.PolicyRef, err)
	}
	return &pol, nil
}

// mapExceptionToScans finds the scans an exception applies to. An exception
// names a model and version rather than a scan, so the lookup is by spec.
func (r *ArtifactScanReconciler) mapExceptionToScans(ctx context.Context, obj client.Object) []reconcile.Request {
	ex, ok := obj.(*securityv1alpha1.ArtifactException)
	if !ok {
		return nil
	}
	var scans securityv1alpha1.ArtifactScanList
	if err := r.List(ctx, &scans, client.InNamespace(ex.Namespace)); err != nil {
		return nil
	}
	var out []reconcile.Request
	for _, s := range scans.Items {
		if s.Spec.ModelName == ex.Spec.ModelName && s.Spec.ModelVersion == ex.Spec.ModelVersion {
			out = append(out, reconcile.Request{
				NamespacedName: client.ObjectKey{Name: s.Name, Namespace: s.Namespace},
			})
		}
	}
	return out
}

func (r *ArtifactScanReconciler) loadExceptions(ctx context.Context, scan *securityv1alpha1.ArtifactScan) ([]securityv1alpha1.ArtifactException, error) {
	var list securityv1alpha1.ArtifactExceptionList
	if err := r.List(ctx, &list, client.InNamespace(scan.Namespace)); err != nil {
		return nil, fmt.Errorf("list exceptions: %w", err)
	}
	return policy.ExceptionsFor(list.Items, scan.Spec.ModelName, scan.Spec.ModelVersion), nil
}

// resolveScanners picks the scanner set: an explicit list on the scan wins,
// then the policy's enabled scanners, then the catalog defaults.
func resolveScanners(scan *securityv1alpha1.ArtifactScan, pol *securityv1alpha1.ArtifactScanPolicy) ([]string, error) {
	var names []string
	switch {
	case len(scan.Spec.Scanners) > 0:
		names = scan.Spec.Scanners
	case pol != nil && len(pol.Spec.Scanners) > 0:
		for _, s := range pol.Spec.Scanners {
			if s.Enabled != nil && !*s.Enabled {
				continue
			}
			names = append(names, s.Name)
		}
	default:
		names = scanners.Defaults()
	}

	for _, name := range names {
		if _, err := scanners.Get(name); err != nil {
			return nil, err
		}
	}
	return names, nil
}

func (r *ArtifactScanReconciler) ensureScanJob(ctx context.Context, scan *securityv1alpha1.ArtifactScan, pol *securityv1alpha1.ArtifactScanPolicy, name string) error {
	def, err := scanners.Get(name)
	if err != nil {
		return err
	}

	jobName := scanJobName(scan.Name, name)
	var existing batchv1.Job
	err = r.Get(ctx, client.ObjectKey{Name: jobName, Namespace: scan.Namespace}, &existing)
	if err == nil {
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return fmt.Errorf("check scan job %s: %w", jobName, err)
	}

	job, err := buildScanJob(scan, def, findScannerSpec(pol, name), r.JobConfig)
	if err != nil {
		return fmt.Errorf("build scan job for %s: %w", name, err)
	}
	if err := controllerutil.SetControllerReference(scan, job, r.Scheme); err != nil {
		return fmt.Errorf("set owner on scan job: %w", err)
	}
	if err := r.Create(ctx, job); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create scan job %s: %w", jobName, err)
	}
	return nil
}

func findScannerSpec(pol *securityv1alpha1.ArtifactScanPolicy, name string) *securityv1alpha1.ScannerSpec {
	if pol == nil {
		return nil
	}
	for i := range pol.Spec.Scanners {
		if pol.Spec.Scanners[i].Name == name {
			return &pol.Spec.Scanners[i]
		}
	}
	return nil
}

// collectResults reads the ArtifactScanReport each publish step wrote, and
// falls back to Job status for scanners that produced no report.
func (r *ArtifactScanReconciler) collectResults(ctx context.Context, scan *securityv1alpha1.ArtifactScan, wanted []string) ([]securityv1alpha1.ScannerResult, int, error) {
	var reports securityv1alpha1.ArtifactScanReportList
	if err := r.List(ctx, &reports, client.InNamespace(scan.Namespace), client.MatchingLabels{LabelScan: scan.Name}); err != nil {
		return nil, 0, fmt.Errorf("list scan reports: %w", err)
	}
	byScanner := map[string]securityv1alpha1.ScannerResult{}
	for i := range reports.Items {
		report := &reports.Items[i]

		// The publish step writes reports without an owner: it runs with a
		// deliberately minimal token that cannot read the ArtifactScan, so it
		// has no UID to point at. Nothing else adopted them either, so they
		// outlived their scan, accumulated in etcd with their full findings
		// arrays, and — because report names are deterministic — a stale one
		// could be mistaken for the current run's result. The controller has
		// the scan in hand, so it adopts them here.
		if err := r.adoptReport(ctx, scan, report); err != nil {
			return nil, 0, err
		}

		summary := report.Summary
		summary.Scanner = report.Scanner
		summary.ReportRef = report.Name
		byScanner[report.Scanner] = summary

		// The fetch step is the only thing that sees the artifact's real bytes,
		// so the digest it measured is the only trustworthy one. It arrives as
		// an annotation on the scan report; record it on the scan so the model
		// report can carry it to the admission gate, which refuses to honour a
		// verdict for a digest other than the one actually scanned.
		if digest := report.Annotations[AnnotationArtifactDigest]; digest != "" {
			scan.Status.ScannedDigest = digest
		}
	}

	var (
		results []securityv1alpha1.ScannerResult
		pending int
	)
	for _, name := range wanted {
		if result, ok := byScanner[name]; ok {
			results = append(results, result)
			continue
		}

		// No report yet: derive interim status from the Job.
		result := securityv1alpha1.ScannerResult{Scanner: name, Status: "Pending"}
		var job batchv1.Job
		err := r.Get(ctx, client.ObjectKey{Name: scanJobName(scan.Name, name), Namespace: scan.Namespace}, &job)
		switch {
		case apierrors.IsNotFound(err):
			result.Status = "Pending"
		case err != nil:
			return nil, 0, fmt.Errorf("get scan job for %s: %w", name, err)
		case job.Status.Failed > 0:
			result.Status = "Error"
			result.Message = "scan job failed; see job logs"
		case job.Status.Active > 0:
			result.Status = "Running"
		case job.Status.Succeeded > 0:
			// The job finished but the report has not landed yet.
			result.Status = "Running"
			result.Message = "waiting for scan report"
		}

		if result.Status != "Error" {
			pending++
		}
		results = append(results, result)
	}
	return results, pending, nil
}

func (r *ArtifactScanReconciler) upsertModelSecurityReport(ctx context.Context, scan *securityv1alpha1.ArtifactScan, eval policy.Evaluation) error {
	if scan.Spec.ModelName == "" || scan.Spec.ModelVersion == "" {
		return nil
	}

	name := modelReportName(scan.Spec.ModelName, scan.Spec.ModelVersion)
	report := &securityv1alpha1.ModelSecurityReport{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: scan.Namespace},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, report, func() error {
		artifact := scan.Spec.Artifact
		// The spec's digest is whatever the registry claimed, and is usually
		// empty. What the gate must compare against is the digest actually
		// measured while staging the bytes, so the measured one wins.
		if scan.Status.ScannedDigest != "" {
			artifact.Digest = scan.Status.ScannedDigest
		}
		report.Spec = securityv1alpha1.ModelSecurityReportSpec{
			ModelName:    scan.Spec.ModelName,
			ModelVersion: scan.Spec.ModelVersion,
			Artifact:     artifact,
			ScanRef:      scan.Name,
		}
		if report.Labels == nil {
			report.Labels = map[string]string{}
		}
		report.Labels[LabelManagedBy] = ManagerName
		report.Labels["security.davano.io/model"] = sanitizeLabel(scan.Spec.ModelName)
		return nil
	})
	if err != nil {
		return fmt.Errorf("upsert model security report: %w", err)
	}

	now := metav1.Now()
	report.Status.Verdict = eval.Verdict
	report.Status.RiskScore = eval.RiskScore
	report.Status.Malware = eval.MalwareStatus
	report.Status.Secrets = eval.SecretsStatus
	report.Status.CVEs = policy.FromCounts(eval.CVEs)
	report.Status.SignatureVerified = eval.SignatureVerified
	report.Status.Scanners = scan.Status.Results
	report.Status.LastScanTime = &now
	report.Status.SBOMRef = sbomRef(scan.Status.Results)
	report.Status.AIBOMRef = refForCategory(scan.Status.Results, scanners.CategoryAIBOM)

	condition := metav1.Condition{
		Type:    "Approved",
		Status:  metav1.ConditionFalse,
		Reason:  "PolicyViolation",
		Message: summarize(eval),
	}
	if eval.Verdict == securityv1alpha1.VerdictApproved {
		condition.Status = metav1.ConditionTrue
		condition.Reason = "PolicyPassed"
	}
	setCondition(&report.Status.Conditions, condition)

	if err := r.Status().Update(ctx, report); err != nil {
		return fmt.Errorf("update model security report status: %w", err)
	}
	return nil
}

// adoptReport makes the ArtifactScan the owner of one of its scan reports, so
// deleting the scan garbage-collects its evidence with it. It is a no-op once
// the reference is in place.
func (r *ArtifactScanReconciler) adoptReport(
	ctx context.Context,
	scan *securityv1alpha1.ArtifactScan,
	report *securityv1alpha1.ArtifactScanReport,
) error {
	if metav1.IsControlledBy(report, scan) {
		return nil
	}
	if err := controllerutil.SetControllerReference(scan, report, r.Scheme); err != nil {
		// Already owned by something else: leave it alone rather than fight
		// over it, and let the scan proceed on the result it carries.
		return nil
	}
	if err := r.Update(ctx, report); err != nil {
		if apierrors.IsConflict(err) || apierrors.IsNotFound(err) {
			// A racing writer or a TTL sweep; the next reconcile retries.
			return nil
		}
		return fmt.Errorf("adopt scan report %s: %w", report.Name, err)
	}
	return nil
}

// DefaultScanDeadline bounds how long a scan may sit unfinished. It is
// comfortably longer than the Job's own ActiveDeadlineSeconds so a slow but
// working scan is never cut off; it exists to catch scans that can no longer
// make progress at all.
const DefaultScanDeadline = 2 * time.Hour

func (r *ArtifactScanReconciler) scanDeadline() time.Duration {
	if r.ScanDeadline > 0 {
		return r.ScanDeadline
	}
	return DefaultScanDeadline
}

// fail marks a scan terminally unsuccessful. The verdict is ReviewRequired
// rather than Approved because an incomplete scan is not evidence of safety.
func (r *ArtifactScanReconciler) fail(ctx context.Context, scan *securityv1alpha1.ArtifactScan, message string) (ctrl.Result, error) {
	now := metav1.Now()
	scan.Status.Phase = "Failed"
	scan.Status.Message = message
	scan.Status.CompletionTime = &now
	scan.Status.Verdict = securityv1alpha1.VerdictReviewRequired
	setCondition(&scan.Status.Conditions, metav1.Condition{
		Type:    "Complete",
		Status:  metav1.ConditionFalse,
		Reason:  "ScanFailed",
		Message: message,
	})
	if err := r.Status().Update(ctx, scan); err != nil {
		return ctrl.Result{}, err
	}
	metrics.ScanVerdicts.WithLabelValues("Failed").Inc()
	return ctrl.Result{}, nil
}

func sbomRef(results []securityv1alpha1.ScannerResult) string {
	return refForCategory(results, scanners.CategorySBOM)
}

// refForCategory finds the report holding a given category's output. The two
// bill-of-materials categories are looked up separately because they describe
// different things: one inventories the packages around a model, the other
// describes the model. Handing a reader the wrong one is worse than handing
// them nothing.
func refForCategory(results []securityv1alpha1.ScannerResult, cat scanners.Category) string {
	for _, r := range results {
		if def, err := scanners.Get(r.Scanner); err == nil && def.Category == cat {
			return r.ReportRef
		}
	}
	return ""
}

func summarize(eval policy.Evaluation) string {
	if len(eval.Violations) == 0 {
		if len(eval.Waived) > 0 {
			return fmt.Sprintf("passed policy with %d waived violation(s)", len(eval.Waived))
		}
		return "passed all policy rules"
	}
	return fmt.Sprintf("%d policy violation(s): %s", len(eval.Violations), eval.Violations[0].String())
}

// SetupWithManager wires the reconciler into the manager.
func (r *ArtifactScanReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.ArtifactScan{}).
		Owns(&batchv1.Job{}).
		Watches(
			&securityv1alpha1.ArtifactScanReport{},
			handler.EnqueueRequestsFromMapFunc(mapReportToScan),
		).
		// Without this an accepted risk would sit in the cluster changing
		// nothing, because the scan it applies to has already finished.
		Watches(
			&securityv1alpha1.ArtifactException{},
			handler.EnqueueRequestsFromMapFunc(r.mapExceptionToScans),
		).
		Named("artifactscan").
		Complete(r)
}

// mapReportToScan requeues the owning scan when a scanner publishes results.
func mapReportToScan(_ context.Context, obj client.Object) []reconcile.Request {
	report, ok := obj.(*securityv1alpha1.ArtifactScanReport)
	if !ok || report.ScanRef == "" {
		return nil
	}
	return []reconcile.Request{{
		NamespacedName: client.ObjectKey{Name: report.ScanRef, Namespace: report.Namespace},
	}}
}

// recordVerdict appends a verdict to the tamper-evident decision log.
//
// Failures are logged and swallowed. The alternative — failing the scan when
// the audit write fails — would trade a recorded verdict for an unrecorded
// one, which is the worse outcome: a missing link in the chain is visible to
// anyone verifying it, whereas a scan that never finished leaves nothing at
// all.
func (r *ArtifactScanReconciler) recordVerdict(
	ctx context.Context, scan *securityv1alpha1.ArtifactScan, eval policy.Evaluation,
) {
	if r.AuditNamespace == "" {
		return
	}
	recorder := &audit.Recorder{Client: r.Client, Namespace: r.AuditNamespace}

	// The measured digest, not the declared one. A verdict belongs to the
	// bytes that were actually staged and scanned; recording what the spec
	// claimed would let the audit trail agree with a URI rather than with
	// content, which is the replay the admission gate exists to refuse.
	digest := scan.Status.ScannedDigest
	if digest == "" {
		digest = scan.Spec.Artifact.Digest
	}
	rec := audit.VerdictIssued(scan.Spec.ModelName, scan.Spec.ModelVersion,
		eval.Verdict, eval.RiskScore, digest)
	// Why the scan ran changes what its verdict means, so it travels with it.
	if scan.Spec.Trigger != "" {
		rec.Detail["trigger"] = scan.Spec.Trigger
	}
	if scan.Spec.TriggeredBy != "" {
		rec.Detail["triggeredBy"] = scan.Spec.TriggeredBy
	}
	if _, err := recorder.Append(ctx, rec); err != nil {
		log.FromContext(ctx).Error(err, "could not record the verdict in the audit log",
			"scan", scan.Name, "verdict", eval.Verdict)
	}
}
