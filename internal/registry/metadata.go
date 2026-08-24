package registry

import (
	"fmt"
	"time"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
)

// Property keys Cupel writes back into the Model Registry. They are namespaced
// so they never collide with user-defined properties.
const (
	PropVerdict      = "cupel.security/verdict"
	PropRiskScore    = "cupel.security/risk-score"
	PropMalware      = "cupel.security/malware"
	PropSecrets      = "cupel.security/secrets"
	PropCVECritical  = "cupel.security/cve-critical"
	PropCVEHigh      = "cupel.security/cve-high"
	PropSigned       = "cupel.security/signature-verified"
	PropLastScan     = "cupel.security/last-scan"
	PropReportRef    = "cupel.security/report"
	PropScannerCount = "cupel.security/scanners-run"
)

// SummaryProperties renders a ModelSecurityReport as registry custom
// properties. Detailed findings deliberately stay in-cluster.
func SummaryProperties(report *securityv1alpha1.ModelSecurityReport) map[string]MetadataValue {
	status := report.Status
	props := map[string]MetadataValue{
		PropVerdict:      StringProperty(orUnknown(status.Verdict)),
		PropRiskScore:    IntProperty(int64(status.RiskScore)),
		PropMalware:      StringProperty(orUnknown(status.Malware)),
		PropSecrets:      StringProperty(orUnknown(status.Secrets)),
		PropCVECritical:  IntProperty(int64(status.CVEs.Critical)),
		PropCVEHigh:      IntProperty(int64(status.CVEs.High)),
		PropSigned:       BoolProperty(status.SignatureVerified),
		PropScannerCount: IntProperty(int64(len(status.Scanners))),
		PropReportRef:    StringProperty(fmt.Sprintf("%s/%s", report.Namespace, report.Name)),
	}
	if status.LastScanTime != nil {
		props[PropLastScan] = StringProperty(status.LastScanTime.UTC().Format(time.RFC3339))
	}
	return props
}

func orUnknown(v string) string {
	if v == "" {
		return securityv1alpha1.VerdictUnknown
	}
	return v
}
