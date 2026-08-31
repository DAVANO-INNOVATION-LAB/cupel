// Package webhook implements the admission gate that stops unapproved models
// from being deployed. It is the enforcement point for everything the scan
// pipeline concludes.
package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/audit"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/controller"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/metrics"
)

// Annotations a workload uses to declare which model it serves. KServe
// InferenceServices are read directly; anything else opts in with these.
const (
	AnnotationModel       = "security.davano.io/model"
	AnnotationVersion     = "security.davano.io/model-version"
	AnnotationEnvironment = "security.davano.io/environment"
	AnnotationPolicy      = "security.davano.io/policy"
	AnnotationSkip        = "security.davano.io/skip-validation"
)

// ModelGate validates that any workload serving a registered model is backed
// by an approved ModelSecurityReport.
type ModelGate struct {
	Client  client.Client
	decoder admission.Decoder

	// DefaultPolicy is consulted for enforcement mode when a workload does
	// not name a policy.
	DefaultPolicy string
	// MaxReportAge is how long an approval stands before the model has to be
	// scanned again. Zero, the default, means an approval never expires.
	//
	// A model version is a mutable pointer in most registries — a branch, a
	// tag — so the bytes behind an approved name can be replaced after the
	// approval was given. The digest check catches that when the workload
	// pins one, and a registry reference usually pins nothing.
	//
	// Off by default because any maximum refuses workloads that are admitted
	// today, and that is the operator's decision to make, not this gate's.
	MaxReportAge time.Duration

	// Now is injectable for tests.
	Now func() time.Time

	// RequireReport rejects workloads that reference a model with no report
	// at all. When false, unknown models are admitted with a warning.
	RequireReport bool
	// Recorder appends admission decisions to the tamper-evident audit chain.
	// Nil disables recording, which is what a cluster running without the
	// audit CRDs gets; the gate still gates.
	Recorder *audit.Recorder

	// ReportNamespace is where the scan pipeline writes its reports — normally
	// the operator's own namespace.
	//
	// A workload and the report about it rarely share a namespace: scans run
	// where the connector runs, while the InferenceService runs wherever the
	// serving team works. Looking only in the workload's namespace meant the
	// gate never found a report, and with RequireReport=false that reads as
	// "unscanned, admit" — the gate silently passed everything it was
	// installed to stop.
	ReportNamespace string
}

// lookupNamespaces is the order the gate searches for cluster state about a
// model: alongside the workload first, so a team that keeps reports next to
// their serving namespace still works, then the pipeline's own namespace.
func (g *ModelGate) lookupNamespaces(workloadNamespace string) []string {
	if g.ReportNamespace == "" || g.ReportNamespace == workloadNamespace {
		return []string{workloadNamespace}
	}
	return []string{workloadNamespace, g.ReportNamespace}
}

// Handle implements admission.Handler.
func (g *ModelGate) Handle(ctx context.Context, req admission.Request) admission.Response {
	start := time.Now()
	outcome := metrics.OutcomeAllowed
	obj := &unstructured.Unstructured{}
	var ref ModelRef
	var reason string

	// One exit point for the record, so a return path added later cannot skip
	// it. That is the failure mode worth designing against here: an audit
	// trail with a hole in it reads exactly like one without.
	defer func() {
		metrics.AdmissionDuration.Observe(time.Since(start).Seconds())
		metrics.AdmissionDecisions.WithLabelValues(outcome, req.Namespace).Inc()
		g.recordDecision(ctx, req, obj, ref, outcome, reason)
	}()

	if req.Operation == admissionv1.Delete {
		return admission.Allowed("")
	}

	if err := json.Unmarshal(req.Object.Raw, obj); err != nil {
		outcome = metrics.OutcomeError
		return admission.Errored(http.StatusBadRequest, fmt.Errorf("decode object: %w", err))
	}

	annotations := obj.GetAnnotations()
	if strings.EqualFold(annotations[AnnotationSkip], "true") {
		// Opting out is recorded in the response so it shows up in the audit
		// log, and counted so a cluster quietly annotating its way around the
		// gate is visible on a dashboard rather than only in the audit trail.
		outcome = metrics.OutcomeAllowedSkipped
		reason = "skip-validation annotation set on the workload"
		ref = extractModelRef(obj)
		return admission.Allowed("cupel validation explicitly skipped by annotation")
	}

	ref = extractModelRef(obj)
	if ref.Model == "" {
		// The workload did not declare a model. Before accepting that at face
		// value, look at what it is actually configured to do: a Deployment
		// mounting a claim of weights into a vLLM image is serving a model
		// whether or not anybody annotated it.
		evidence := discoverModelEvidence(obj)
		if len(evidence) == 0 {
			return admission.Allowed("no model reference and no sign this workload serves one")
		}

		ref = refFromEvidence(evidence)
		if ref.Model == "" {
			// Intent without identity. Saying "nothing to validate" here would
			// be false, and it is the sentence an operator reads as assurance.
			reason = "workload serves a model it does not identify: " + describeEvidence(evidence)
			if g.RequireReport {
				outcome = metrics.OutcomeDenied
				return admission.Denied(fmt.Sprintf(
					"this workload appears to serve a model (%s) and does not identify which one; "+
						"annotate it with %s and %s, or set %s=true to accept the risk explicitly",
					describeEvidence(evidence), AnnotationModel, AnnotationVersion, AnnotationSkip))
			}
			outcome = metrics.OutcomeAllowedUnidentified
			resp := admission.Allowed("cupel: model could not be identified")
			resp.Warnings = append(resp.Warnings, fmt.Sprintf(
				"cupel: this workload appears to serve a model (%s) but does not identify which one, "+
					"so no scan verdict was applied", describeEvidence(evidence)))
			return resp
		}
	}

	report, err := g.findReport(ctx, req.Namespace, ref)
	if err != nil {
		outcome = metrics.OutcomeError
		return admission.Errored(http.StatusInternalServerError, fmt.Errorf("look up security report: %w", err))
	}
	if report == nil {
		reason = fmt.Sprintf("no security report for model %q version %q", ref.Model, ref.Version)
		if g.RequireReport {
			outcome = metrics.OutcomeDenied
			return admission.Denied(fmt.Sprintf(
				"model %q version %q has not been scanned by Cupel; register it and wait for the scan to complete",
				ref.Model, ref.Version))
		}
		// Admitted only because Cupel knows nothing about this model. Counted
		// separately from a real approval: the two are opposite facts that look
		// identical from outside.
		outcome = metrics.OutcomeAllowedNoScan
		return admission.Allowed(fmt.Sprintf("no Cupel security report for model %q version %q", ref.Model, ref.Version))
	}

	enforcement := g.enforcementFor(ctx, req.Namespace, annotations)
	promotion := g.promotionModeFor(ctx, req.Namespace, annotations)

	if decision := g.evaluate(report, ref, promotion); decision.deny {
		reason = decision.reason
		switch enforcement {
		case "Audit":
			outcome = metrics.OutcomeAllowedAudit
			return admission.Allowed("cupel: " + decision.reason + " (audit mode)")
		case "Warn":
			outcome = metrics.OutcomeAllowedWarn
			resp := admission.Allowed("cupel: admitted with warnings")
			resp.Warnings = append(resp.Warnings, "cupel: "+decision.reason)
			return resp
		default:
			outcome = metrics.OutcomeDenied
			return admission.Denied("cupel: " + decision.reason)
		}
	}

	return admission.Allowed(fmt.Sprintf(
		"cupel: model %q version %q approved (risk score %d)", ref.Model, ref.Version, report.Status.RiskScore))
}

// findReport returns the security report for a model, or nil when none exists.
// A genuine API error is returned as an error so the caller can fail per the
// webhook's failurePolicy rather than mistaking an outage for "not scanned".
func (g *ModelGate) findReport(ctx context.Context, workloadNamespace string, ref ModelRef) (*securityv1alpha1.ModelSecurityReport, error) {
	// Current name first, then the name reports were written under before they
	// carried a fingerprint. Whichever matches, the report still has to say it
	// is about this model.
	names := controller.ModelReportNames(ref.Model, ref.Version)
	for _, ns := range g.lookupNamespaces(workloadNamespace) {
		for _, name := range names {
			report := &securityv1alpha1.ModelSecurityReport{}
			err := g.Client.Get(ctx, client.ObjectKey{Name: name, Namespace: ns}, report)
			if err == nil {
				// The object name is derived from the model identity, and
				// deriving it loses information: identifiers arrive from a
				// registry and are flattened into something Kubernetes will
				// accept. The fingerprint keeps current names apart; this check
				// is what makes a legacy name safe to read, and covers any
				// derivation nobody has thought of yet.
				if !reportDescribes(report, ref) {
					continue
				}
				return report, nil
			}
			if client.IgnoreNotFound(err) != nil {
				return nil, err
			}
		}
	}
	return nil, nil
}

// reportDescribes reports whether a security report is about the model being
// admitted, rather than one whose name merely derives to the same string.
//
// A mismatch is treated as no report at all: it is not evidence about this
// model, and the safe reading of "no evidence" is whatever the operator chose
// with --require-report, not somebody else's approval.
func reportDescribes(report *securityv1alpha1.ModelSecurityReport, ref ModelRef) bool {
	// An older report written before the operator recorded the identity has
	// nothing to compare against. Accepting it keeps upgrades working; it is
	// no weaker than the behaviour it replaces.
	if report.Spec.ModelName == "" {
		return true
	}
	if report.Spec.ModelName != ref.Model {
		return false
	}
	// Version is compared only when both sides state one, for the same reason.
	if report.Spec.ModelVersion != "" && ref.Version != "" {
		return report.Spec.ModelVersion == ref.Version
	}
	return true
}

type decision struct {
	deny   bool
	reason string
}

func (g *ModelGate) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

// roundAge renders a duration the way somebody reading a denial would say it,
// rather than as hours to the nanosecond.
func roundAge(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	case d >= 2*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	default:
		return d.Round(time.Minute).String()
	}
}

func (g *ModelGate) evaluate(report *securityv1alpha1.ModelSecurityReport, ref ModelRef, promotion string) decision {
	switch report.Status.Verdict {
	case securityv1alpha1.VerdictApproved:
		// keep going: an approved model may still be unpromoted for this env
	case securityv1alpha1.VerdictQuarantined:
		return decision{true, fmt.Sprintf(
			"model %q version %q is quarantined (risk score %d, malware: %s)",
			ref.Model, ref.Version, report.Status.RiskScore, orUnknown(report.Status.Malware))}
	case securityv1alpha1.VerdictReviewRequired:
		return decision{true, fmt.Sprintf(
			"model %q version %q requires security review before deployment (risk score %d)",
			ref.Model, ref.Version, report.Status.RiskScore)}
	default:
		return decision{true, fmt.Sprintf(
			"model %q version %q has no completed scan verdict", ref.Model, ref.Version)}
	}

	// An approval older than the operator's limit is not an approval any more.
	//
	// This can only take an approval away, never grant one: every other verdict
	// has already returned above. Staleness must not rescue a denial.
	if g.MaxReportAge > 0 {
		scanned := report.Status.LastScanTime
		if scanned == nil {
			return decision{true, fmt.Sprintf(
				"model %q version %q carries an approval with no scan time, so it cannot be "+
					"shown to be within the %s freshness limit; rescan it",
				ref.Model, ref.Version, g.MaxReportAge)}
		}
		if age := g.now().Sub(scanned.Time); age > g.MaxReportAge {
			return decision{true, fmt.Sprintf(
				"model %q version %q was last scanned %s ago, beyond the %s freshness limit; "+
					"rescan it before deploying",
				ref.Model, ref.Version, roundAge(age), g.MaxReportAge)}
		}
	}

	// The digest pinned in the workload must match what was actually scanned,
	// otherwise an approved verdict could be replayed onto different bytes.
	if ref.Digest != "" && report.Spec.Artifact.Digest != "" && ref.Digest != report.Spec.Artifact.Digest {
		return decision{true, fmt.Sprintf(
			"artifact digest %s does not match the scanned digest %s",
			ref.Digest, report.Spec.Artifact.Digest)}
	}

	// The environment gate, and the case that made it backwards.
	//
	// ApprovedEnvironments is written only by an approved PromotionRequest, so
	// an empty list means "nobody has promoted this version anywhere". Guarding
	// the check on len() > 0 therefore skipped it precisely when nothing had
	// been approved: a version promoted to dev was refused prod, while a version
	// promoted nowhere sailed through. The gate was weakest for the artifacts
	// with the least scrutiny, which is the shape every fail-open takes.
	//
	// Ignore restores the old behaviour for clusters that annotate an
	// environment without running promotions at all.
	if ref.Environment != "" {
		if len(report.Status.ApprovedEnvironments) == 0 {
			if promotion != PromotionIgnore {
				return decision{true, fmt.Sprintf(
					"model %q version %q is not promoted to any environment, and this workload "+
						"declares %q; approve a PromotionRequest, or set spec.environmentPromotion: "+
						"Ignore on the policy if this cluster does not use promotions",
					ref.Model, ref.Version, ref.Environment)}
			}
		} else if !contains(report.Status.ApprovedEnvironments, ref.Environment) {
			return decision{true, fmt.Sprintf(
				"model %q version %q is not promoted to %q (approved for: %s)",
				ref.Model, ref.Version, ref.Environment,
				strings.Join(report.Status.ApprovedEnvironments, ", "))}
		}
	}

	return decision{}
}

// enforcementFor resolves the enforcement mode from the named policy, the
// namespace default policy, or the operator default.
func (g *ModelGate) enforcementFor(ctx context.Context, namespace string, annotations map[string]string) string {
	name := annotations[AnnotationPolicy]
	if name == "" {
		name = g.DefaultPolicy
	}
	if name == "" {
		return "Enforce"
	}

	// Policies live beside the scans that use them, which is usually not the
	// workload's namespace — same split as the reports themselves.
	for _, ns := range g.lookupNamespaces(namespace) {
		var pol securityv1alpha1.ArtifactScanPolicy
		if err := g.Client.Get(ctx, client.ObjectKey{Name: name, Namespace: ns}, &pol); err != nil {
			continue
		}
		if pol.Spec.Enforcement == "" {
			return "Enforce"
		}
		return pol.Spec.Enforcement
	}
	// A missing policy must not weaken the gate.
	return "Enforce"
}

// InjectDecoder satisfies controller-runtime's decoder injection.
func (g *ModelGate) InjectDecoder(d admission.Decoder) error {
	g.decoder = d
	return nil
}

// SetupWithManager registers the gate on the manager's webhook server.
func (g *ModelGate) SetupWithManager(mgr ctrl.Manager) error {
	if g.Client == nil {
		g.Client = mgr.GetClient()
	}
	g.decoder = admission.NewDecoder(mgr.GetScheme())
	mgr.GetWebhookServer().Register("/validate-model-deployment", &admission.Webhook{Handler: g})
	return nil
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if strings.EqualFold(item, value) {
			return true
		}
	}
	return false
}

func orUnknown(v string) string {
	if v == "" {
		return "unknown"
	}
	return v
}

// Promotion modes for spec.environmentPromotion.
const (
	// PromotionRequire treats "promoted nowhere" as "not promoted here".
	PromotionRequire = "Require"
	// PromotionIgnore skips the environment check when nothing is promoted.
	PromotionIgnore = "Ignore"
)

// promotionModeFor resolves the promotion mode from the named policy, the
// namespace default policy, or the operator default.
//
// Defaults to Require. A policy that cannot be read yields the safe answer
// rather than the permissive one — the reverse is how an unreachable API server
// turns into an open gate.
func (g *ModelGate) promotionModeFor(ctx context.Context, namespace string, annotations map[string]string) string {
	name := annotations[AnnotationPolicy]
	if name == "" {
		name = g.DefaultPolicy
	}
	if name == "" {
		return PromotionRequire
	}
	for _, ns := range g.lookupNamespaces(namespace) {
		var pol securityv1alpha1.ArtifactScanPolicy
		if err := g.Client.Get(ctx, client.ObjectKey{Name: name, Namespace: ns}, &pol); err != nil {
			continue
		}
		if pol.Spec.EnvironmentPromotion == PromotionIgnore {
			return PromotionIgnore
		}
		return PromotionRequire
	}
	return PromotionRequire
}
