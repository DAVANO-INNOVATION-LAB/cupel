package webhook

import (
	"strings"
	"testing"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/assay/api/v1alpha1"
)

func approvedReport(envs ...string) *securityv1alpha1.ModelSecurityReport {
	r := &securityv1alpha1.ModelSecurityReport{}
	r.Status.Verdict = securityv1alpha1.VerdictApproved
	r.Status.ApprovedEnvironments = envs
	return r
}

// The fail-open this closes, stated as a test so it cannot quietly reopen.
//
// ApprovedEnvironments is written only by an approved PromotionRequest, so an
// empty list means nobody has promoted this version anywhere. Guarding the
// environment check on len() > 0 skipped it precisely when nothing had been
// approved: a version promoted to dev was refused prod, while a version
// promoted nowhere sailed into prod unchallenged. The gate was weakest for the
// artifacts with the least scrutiny.
func TestUnpromotedVersionIsRefusedAnEnvironment(t *testing.T) {
	g := &ModelGate{}
	ref := ModelRef{Model: "fraud", Version: "v3", Environment: "prod"}

	d := g.evaluate(approvedReport(), ref, PromotionRequire)
	if !d.deny {
		t.Fatal("a version promoted nowhere was admitted to prod")
	}
	if !strings.Contains(d.reason, "not promoted to any environment") {
		t.Errorf("unhelpful reason: %q", d.reason)
	}
	// The message has to name the way out, or an operator whose cluster does
	// not use promotions has an outage and no next step.
	if !strings.Contains(d.reason, "environmentPromotion") {
		t.Errorf("the denial does not say how to opt out: %q", d.reason)
	}
}

// Ignore restores the old behaviour for clusters that annotate an environment
// without running promotions at all.
func TestIgnoreModeSkipsTheEnvironmentCheckWhenNothingIsPromoted(t *testing.T) {
	g := &ModelGate{}
	ref := ModelRef{Model: "fraud", Version: "v3", Environment: "prod"}

	if d := g.evaluate(approvedReport(), ref, PromotionIgnore); d.deny {
		t.Errorf("Ignore mode denied: %q", d.reason)
	}
}

// Promotion to one environment must not admit another, in either mode. This is
// the behaviour that already worked and must keep working.
func TestPromotionToOneEnvironmentDoesNotAdmitAnother(t *testing.T) {
	g := &ModelGate{}
	ref := ModelRef{Model: "fraud", Version: "v3", Environment: "prod"}

	for _, mode := range []string{PromotionRequire, PromotionIgnore} {
		d := g.evaluate(approvedReport("dev", "stage"), ref, mode)
		if !d.deny {
			t.Errorf("%s: a dev/stage promotion admitted prod", mode)
		}
		if !strings.Contains(d.reason, "dev, stage") {
			t.Errorf("%s: the denial does not say where it IS approved: %q", mode, d.reason)
		}
	}
}

// A workload declaring no environment is not opting into environment gating,
// and must be unaffected in both modes.
func TestWorkloadWithNoEnvironmentIsUnaffected(t *testing.T) {
	g := &ModelGate{}
	ref := ModelRef{Model: "fraud", Version: "v3"}

	for _, mode := range []string{PromotionRequire, PromotionIgnore} {
		if d := g.evaluate(approvedReport(), ref, mode); d.deny {
			t.Errorf("%s: denied a workload that declares no environment: %q", mode, d.reason)
		}
	}
}

// And the promoted case still admits.
func TestPromotedVersionIsAdmitted(t *testing.T) {
	g := &ModelGate{}
	ref := ModelRef{Model: "fraud", Version: "v3", Environment: "prod"}
	if d := g.evaluate(approvedReport("dev", "prod"), ref, PromotionRequire); d.deny {
		t.Errorf("a promoted version was denied: %q", d.reason)
	}
}
