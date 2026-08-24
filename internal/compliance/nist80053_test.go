package compliance

import (
	"strings"
	"testing"
)

func TestNIST80053CatalogLoads(t *testing.T) {
	c := NIST80053()
	if c.Framework != NIST80053R5 {
		t.Fatalf("wrong framework: %s", c.Framework)
	}
	if len(c.Controls()) == 0 {
		t.Fatal("catalog is empty")
	}
	if _, err := c.Get("CM-14"); err != nil {
		t.Fatalf("CM-14 Signed Components is the closest fit for the admission gate and must be present: %v", err)
	}
}

// The distinction this whole file rests on: Cupel contributes evidence toward
// a control. It does not satisfy one. If a control claims Full automation it
// must at least name the evidence that backs the claim.
func TestEveryClaimNamesItsEvidence(t *testing.T) {
	for _, ctrl := range NIST80053().Controls() {
		if ctrl.Rationale == "" {
			t.Errorf("%s has no rationale", ctrl.ID)
		}
		switch ctrl.Automation {
		case AutomationNone:
			if len(ctrl.Evidence) > 0 {
				t.Errorf("%s claims no automation but names evidence %v", ctrl.ID, ctrl.Evidence)
			}
		default:
			if len(ctrl.Evidence) == 0 {
				t.Errorf("%s claims %s automation but names no evidence", ctrl.ID, ctrl.Automation)
			}
		}
	}
}

// Controls Cupel cannot speak to are in the catalogue on purpose. Dropping
// them would turn a subset into something that reads like full coverage.
func TestGapsAreRecordedRatherThanOmitted(t *testing.T) {
	c := NIST80053()
	var none int
	for _, ctrl := range c.Controls() {
		if ctrl.Automation == AutomationNone {
			none++
		}
	}
	if none == 0 {
		t.Fatal("a mapping with nothing marked unobservable is not an honest subset")
	}

	// SA-11 asks whether the model's *developer* tested it. Cupel assesses an
	// artifact it is handed and cannot know.
	sa11, err := c.Get("SA-11")
	if err != nil {
		t.Fatal(err)
	}
	if sa11.Automation != AutomationNone {
		t.Error("SA-11 concerns the developer's testing, which Cupel cannot observe")
	}
}

// AU-9 is the one where overclaiming would be most damaging: a hash chain
// makes tampering evident, not impossible.
func TestAuditProtectionIsNotClaimedAsFull(t *testing.T) {
	ctrl, err := NIST80053().Get("AU-9")
	if err != nil {
		t.Fatal(err)
	}
	if ctrl.Automation == AutomationFull {
		t.Fatal("a hash chain makes modification evident, not prevented; claiming Full here " +
			"would not survive an assessor asking who can rewrite the store")
	}
	if !strings.Contains(ctrl.Rationale, "evident") {
		t.Error("the rationale should state the evident-versus-prevented distinction")
	}
}

func TestCatalogsAreIndependent(t *testing.T) {
	ai, sp := NISTAIRMF(), NIST80053()
	if ai.Framework == sp.Framework {
		t.Fatal("the two catalogues must report different frameworks")
	}
	// An AI RMF subcategory must not resolve against 800-53.
	if _, err := sp.Get("GOVERN 1.1"); err == nil {
		t.Fatal("an AI RMF id should not resolve in the 800-53 catalogue")
	}
}
