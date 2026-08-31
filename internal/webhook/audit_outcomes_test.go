package webhook

import (
	"testing"

	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/metrics"
)

// Every outcome that is not an ordinary approval must reach the audit chain.
//
// This test exists because of how the set fails: an outcome added to the gate
// and not added here is metered but never recorded, and it fails silently into
// the one bucket that is omitted on purpose. Nothing about a missing chain
// entry looks different from an approval that was never interesting. Listing
// the exemptions explicitly means the next outcome added has to make a
// decision here rather than inherit one.
func TestEveryNonOrdinaryOutcomeIsAuditable(t *testing.T) {
	// The two deliberate exemptions:
	//   OutcomeAllowed — an ordinary approval, reconstructable from the report.
	//   OutcomeError   — the gate reached no decision; the API server's
	//                    failurePolicy settles what happens, and there is no
	//                    verdict to record.
	exempt := map[string]string{
		metrics.OutcomeAllowed: "ordinary approval, reconstructable from the report",
		metrics.OutcomeError:   "no decision was reached",
	}

	all := []string{
		metrics.OutcomeAllowed,
		metrics.OutcomeDenied,
		metrics.OutcomeAllowedNoScan,
		metrics.OutcomeAllowedAudit,
		metrics.OutcomeAllowedWarn,
		metrics.OutcomeAllowedSkipped,
		metrics.OutcomeAllowedUnidentified,
		metrics.OutcomeAllowedUnexamined,
		metrics.OutcomeError,
	}

	for _, outcome := range all {
		if _, ok := exempt[outcome]; ok {
			if auditableOutcomes[outcome] {
				t.Errorf("outcome %q is exempt (%s) but marked auditable", outcome, exempt[outcome])
			}
			continue
		}
		if !auditableOutcomes[outcome] {
			t.Errorf("outcome %q is not auditable; a decision that never reaches the chain "+
				"is indistinguishable from one that was never interesting", outcome)
		}
	}
}
