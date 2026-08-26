package integration

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/controller"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/naming"
	cupelwebhook "github.com/DAVANO-INNOVATION-LAB/cupel/internal/webhook"
)

func reportNamed(name, model, version, verdict string) *securityv1alpha1.ModelSecurityReport {
	r := &securityv1alpha1.ModelSecurityReport{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ml"},
		Spec: securityv1alpha1.ModelSecurityReportSpec{
			ModelName: model, ModelVersion: version,
		},
	}
	r.Status.Verdict = verdict
	r.Status.RiskScore = 4
	r.Status.LastScanTime = &metav1.Time{Time: time.Now()}
	return r
}

func gateOver(t *testing.T, objs ...client.Object) *cupelwebhook.ModelGate {
	t.Helper()
	scheme := admissionScheme(t)
	g := &cupelwebhook.ModelGate{
		Client:        fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build(),
		RequireReport: true,
	}
	if err := g.InjectDecoder(admission.NewDecoder(scheme)); err != nil {
		t.Fatal(err)
	}
	return g
}

// The upgrade case. Names now carry a fingerprint, so every report written by
// an older operator sits under a name this one would not compute. If the gate
// only looked for the new name it would find nothing for every model in the
// cluster — and on the default setting, that admits everything.
func TestAReportWrittenBeforeTheUpgradeIsStillFound(t *testing.T) {
	const model, version = "acme-fraud", "v1"

	legacy := naming.LegacyModelReport(model, version)
	current := controller.ModelReportName(model, version)
	if legacy == current {
		t.Fatal("fixture no longer exercises the upgrade: both names are the same")
	}
	t.Logf("written by the old operator as %s", legacy)
	t.Logf("this operator would write     %s", current)

	g := gateOver(t, reportNamed(legacy, model, version, "Approved"))
	resp := g.Handle(context.Background(), deploymentFor(t, model, version))
	if !resp.Allowed {
		t.Fatalf("a model approved before the upgrade was refused: %q", resp.Result.Message)
	}

	// And a refusal written before the upgrade must still refuse.
	blocked := gateOver(t, reportNamed(legacy, model, version, "Quarantined"))
	if r := blocked.Handle(context.Background(), deploymentFor(t, model, version)); r.Allowed {
		t.Fatal("a model quarantined before the upgrade was admitted after it")
	}
}

// Once rescanned, the report exists under both names. The current one wins, so
// a fresh verdict is never shadowed by a stale one left behind by the upgrade.
func TestTheCurrentNameWinsOverALeftoverOne(t *testing.T) {
	const model, version = "acme-fraud", "v1"

	g := gateOver(t,
		reportNamed(naming.LegacyModelReport(model, version), model, version, "Approved"),
		reportNamed(controller.ModelReportName(model, version), model, version, "Quarantined"),
	)
	resp := g.Handle(context.Background(), deploymentFor(t, model, version))
	if resp.Allowed {
		t.Fatal("a stale approval under the old name overrode a current quarantine")
	}
}

// Reading the old name must not reopen what the old name made possible: two
// models still flatten to one legacy name, and the report has to say which
// model it is about.
func TestTheLegacyNameStillCannotBeBorrowed(t *testing.T) {
	// Written for acme-fraud, under a name acme/fraud also flattens to.
	legacy := naming.LegacyModelReport("acme-fraud", "v1")
	if legacy != naming.LegacyModelReport("acme/fraud", "v1") {
		t.Fatal("fixture no longer exercises the collision")
	}

	g := gateOver(t, reportNamed(legacy, "acme-fraud", "v1", "Approved"))
	resp := g.Handle(context.Background(), deploymentFor(t, "acme/fraud", "v1"))
	if resp.Allowed {
		t.Fatalf("a different model borrowed an approval through the legacy name: %q",
			resp.Result.Message)
	}
}
