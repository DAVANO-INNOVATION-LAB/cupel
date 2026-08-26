package integration

import (
	"context"
	"encoding/binary"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/controller"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/policy"
	cupelwebhook "github.com/DAVANO-INNOVATION-LAB/cupel/internal/webhook"
)

func ggufBytes(version uint32, tensors, kv uint64) []byte {
	b := []byte("GGUF")
	b = binary.LittleEndian.AppendUint32(b, version)
	b = binary.LittleEndian.AppendUint64(b, tensors)
	b = binary.LittleEndian.AppendUint64(b, kv)
	return b
}

func validGGUF() []byte {
	var b []byte
	p32 := func(v uint32) { var x [4]byte; binary.LittleEndian.PutUint32(x[:], v); b = append(b, x[:]...) }
	p64 := func(v uint64) { var x [8]byte; binary.LittleEndian.PutUint64(x[:], v); b = append(b, x[:]...) }
	str := func(s string) { p64(uint64(len(s))); b = append(b, s...) }

	b = append(b, "GGUF"...)
	p32(3)
	p64(1)
	p64(2)
	str("general.architecture")
	p32(8)
	str("llama")
	str("general.name")
	p32(8)
	str("ordinary-model")
	str("blk.0.weight")
	p32(2)
	p64(4096)
	p64(4096)
	p32(1)
	p64(0)
	return b
}

// A GGUF the scanner cannot read must not scan as though it were clean.
//
// It used to. The file was identified as GGUF, never examined, and produced a
// report indistinguishable from a clean model's. This walks the real path: the
// scanner, the policy engine, the report the controller writes, and the
// admission webhook.
func TestAMalformedGGUFIsSeenByTheScanner(t *testing.T) {
	scheme := admissionScheme(t)

	cases := []struct {
		name        string
		bytes       []byte
		wantFinding bool
	}{
		{"claims 2^64 tensors", ggufBytes(3, math.MaxUint64, 4), true},
		{"claims 2^64 metadata entries", ggufBytes(3, 4, math.MaxUint64), true},
		{"is not GGUF at all", []byte("NOPE\x00\x00\x00\x00"), true},
		{"an ordinary model", validGGUF(), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "model.gguf"), tc.bytes, 0o644); err != nil {
				t.Fatal(err)
			}

			result := runInspectorStage(t, dir)
			eval := policy.Evaluate(
				[]securityv1alpha1.ScannerResult{result},
				securityv1alpha1.ArtifactRef{URI: "pvc://claim/m"},
				nil, nil, time.Now(),
			)

			report := &securityv1alpha1.ModelSecurityReport{
				ObjectMeta: metav1.ObjectMeta{
					Name: controller.ModelReportName("m", "v1"), Namespace: "ml",
				},
				Spec: securityv1alpha1.ModelSecurityReportSpec{ModelName: "m", ModelVersion: "v1"},
			}
			report.Status.Verdict = eval.Verdict
			report.Status.RiskScore = eval.RiskScore
			report.Status.LastScanTime = &metav1.Time{Time: time.Now()}

			gate := &cupelwebhook.ModelGate{
				Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(report).Build(),
			}
			if err := gate.InjectDecoder(admission.NewDecoder(scheme)); err != nil {
				t.Fatal(err)
			}
			resp := gate.Handle(context.Background(), deploymentFor(t, "m", "v1"))

			t.Logf("%-30s findings=%d risk=%d verdict=%s admitted=%v",
				tc.name, result.Findings, eval.RiskScore, eval.Verdict, resp.Allowed)

			switch {
			case tc.wantFinding && result.Findings == 0:
				t.Error("scanned clean: this reads to an approver exactly like a model " +
					"that was examined and found sound")
			case tc.wantFinding && eval.RiskScore == 0:
				t.Error("a finding was raised but carried no risk weight at all")
			case !tc.wantFinding && result.Findings != 0:
				t.Errorf("%d findings on an ordinary model: this would flag real deployments",
					result.Findings)
			}
		})
	}
}

// The gap this closed. A file the scanner identified and could not read used to
// come back Approved under every rule the policy language had — the verdict is
// built from rule violations, and nothing described coverage, so there was
// nothing for a rule to match on.
func TestAnUnreadableArtifactCanNowBeRefused(t *testing.T) {
	dir := t.TempDir()
	// Truncated after the magic bytes: the scanner recognises the format and
	// cannot read the header. An implausible tensor count would not do — that
	// is a finding about what is in the file, not about what was not read.
	if err := os.WriteFile(filepath.Join(dir, "model.gguf"), []byte("GGUF"), 0o644); err != nil {
		t.Fatal(err)
	}

	result := runInspectorStage(t, dir)
	if result.Findings == 0 {
		t.Fatal("precondition: the scanner should report this file")
	}
	if result.Unexamined.Critical+result.Unexamined.High+result.Unexamined.Medium+
		result.Unexamined.Low+result.Unexamined.Unknown == 0 {
		t.Fatal("precondition: the finding should be counted as coverage, not only as severity")
	}

	artifact := securityv1alpha1.ArtifactRef{URI: "pvc://claim/m"}
	results := []securityv1alpha1.ScannerResult{result}

	// Off, which is the default: unchanged from before.
	loose := &securityv1alpha1.ArtifactScanPolicy{}
	loose.Spec.Rules = securityv1alpha1.PolicyRules{BlockUnsafeModel: ptr(true)}
	if v := policy.Evaluate(results, artifact, loose, nil, time.Now()); v.Verdict != "Approved" {
		t.Errorf("with the rule off the verdict changed to %q; existing clusters would "+
			"start refusing what they admit today", v.Verdict)
	}

	// On, and it refuses.
	strict := &securityv1alpha1.ArtifactScanPolicy{}
	strict.Spec.Rules = securityv1alpha1.PolicyRules{
		BlockUnsafeModel: ptr(true), BlockUnexamined: ptr(true),
	}
	eval := policy.Evaluate(results, artifact, strict, nil, time.Now())
	t.Logf("with blockUnexamined: verdict=%s violations=%d", eval.Verdict, len(eval.Violations))
	if eval.Verdict == "Approved" {
		t.Fatal("a file the scanner could not read was still approved")
	}

	// ...and the workload is refused end to end.
	scheme := admissionScheme(t)
	report := &securityv1alpha1.ModelSecurityReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: controller.ModelReportName("m", "v1"), Namespace: "ml",
		},
		Spec: securityv1alpha1.ModelSecurityReportSpec{ModelName: "m", ModelVersion: "v1"},
	}
	report.Status.Verdict = eval.Verdict
	report.Status.RiskScore = eval.RiskScore
	report.Status.LastScanTime = &metav1.Time{Time: time.Now()}

	gate := &cupelwebhook.ModelGate{
		Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(report).Build(),
	}
	if err := gate.InjectDecoder(admission.NewDecoder(scheme)); err != nil {
		t.Fatal(err)
	}
	if resp := gate.Handle(context.Background(), deploymentFor(t, "m", "v1")); resp.Allowed {
		t.Fatal("the workload was admitted for a model nobody could read")
	}
}

// An ordinary model must not trip the rule, or it is unusable.
func TestAnOrdinaryModelIsUnaffectedByTheRule(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "model.gguf"), validGGUF(), 0o644); err != nil {
		t.Fatal(err)
	}
	result := runInspectorStage(t, dir)

	strict := &securityv1alpha1.ArtifactScanPolicy{}
	strict.Spec.Rules = securityv1alpha1.PolicyRules{
		BlockUnsafeModel: ptr(true), BlockUnexamined: ptr(true),
	}
	eval := policy.Evaluate([]securityv1alpha1.ScannerResult{result},
		securityv1alpha1.ArtifactRef{URI: "pvc://claim/m"}, strict, nil, time.Now())
	if eval.Verdict != "Approved" {
		t.Fatalf("an ordinary model was refused under blockUnexamined: %q — %d violations",
			eval.Verdict, len(eval.Violations))
	}
}

func ptr[T any](v T) *T { return &v }
