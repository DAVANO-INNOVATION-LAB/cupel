package controller

import (
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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

func scanNameFor(model, version, artifactID string) string {
	return naming.Scan(model, version, artifactID)
}

func scanJobName(scanName, scanner string) string {
	return naming.ScanJob(scanName, scanner)
}

func sanitizeLabel(value string) string {
	return naming.SanitizeLabel(value)
}
