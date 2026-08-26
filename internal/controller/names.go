package controller

import (
	"context"

	batchv1 "k8s.io/api/batch/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/naming"
)

// setCondition upserts a status condition, filling in the transition time.
func setCondition(conditions *[]metav1.Condition, condition metav1.Condition) {
	if condition.LastTransitionTime.IsZero() {
		condition.LastTransitionTime = metav1.Now()
	}
	apimeta.SetStatusCondition(conditions, condition)
}

// ModelReportName is the ModelSecurityReport name for a model version. It is
// exported because the admission webhook must derive the same name to find
// the report the scan pipeline wrote.
func ModelReportName(model, version string) string {
	return naming.ModelReport(model, version)
}

func modelReportName(model, version string) string {
	return naming.ModelReport(model, version)
}

// ModelReportNames are the names a model's report may be stored under, current
// first.
//
// Names gained a fingerprint so that two models could stop deriving the same
// one. Reports written before that are still the only record of a scan that
// really happened, so a reader has to look under the old name too — and a
// lookup that finds one is checked against the report's own contents, which is
// what makes tolerating the ambiguous name safe.
func ModelReportNames(model, version string) []string {
	current := naming.ModelReport(model, version)
	legacy := naming.LegacyModelReport(model, version)
	if legacy == current {
		return []string{current}
	}
	return []string{current, legacy}
}

func scanNameFor(model, version, artifactID string) string {
	return naming.Scan(model, version, artifactID)
}

func scanJobName(scanName, scanner string) string {
	return naming.ScanJob(scanName, scanner)
}

// scanJobNames are the names a scan's Job may exist under, current first.
//
// Job names are derived, and the derivation changed when names gained a
// fingerprint. A scan that was already running when the operator was upgraded
// has a Job under the old name; computing only the new one would find nothing
// and start a second Job to do work already in flight.
func scanJobNames(scanName, scanner string) []string {
	current := naming.ScanJob(scanName, scanner)
	legacy := naming.LegacyStable("", scanName, scanner)
	if legacy == current {
		return []string{current}
	}
	return []string{current, legacy}
}

// findScanJob returns a scan's Job under whichever name it exists, or false.
func (r *ArtifactScanReconciler) findScanJob(
	ctx context.Context, namespace, scanName, scanner string,
) (*batchv1.Job, bool, error) {
	for _, name := range scanJobNames(scanName, scanner) {
		var job batchv1.Job
		err := r.Get(ctx, client.ObjectKey{Name: name, Namespace: namespace}, &job)
		switch {
		case apierrors.IsNotFound(err):
			continue
		case err != nil:
			return nil, false, err
		}
		return &job, true, nil
	}
	return nil, false, nil
}

func sanitizeLabel(value string) string {
	return naming.SanitizeLabel(value)
}
