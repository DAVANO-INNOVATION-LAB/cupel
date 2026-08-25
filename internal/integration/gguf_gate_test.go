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

// Known limitation, recorded so it cannot be mistaken for working.
//
// The verdict is decided by policy-rule violations, not by findings, and no
// rule covers "a scanner identified this format and could not read it". That is
// not specific to GGUF: the equivalent findings for Keras, ONNX and plain IO
// errors are all Medium and none of them has ever affected a verdict either.
//
// Closing it needs the gate to be able to see *which* findings were raised
// rather than only how many and how severe, which is a change to what scanners
// report — and a decision about whether an unreadable artifact should be
// refused by default. Until then, an operator cannot express "block what could
// not be read", and this test says so out loud rather than leaving a green
// suite to imply otherwise.
func TestAnUnreadableArtifactCannotYetBeBlockedByPolicy(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "model.gguf"),
		ggufBytes(3, math.MaxUint64, 4), 0o644); err != nil {
		t.Fatal(err)
	}

	result := runInspectorStage(t, dir)
	if result.Findings == 0 {
		t.Fatal("precondition: the scanner should now report this file")
	}

	// Every rule the policy can express, set as strictly as it goes.
	strict := &securityv1alpha1.ArtifactScanPolicy{}
	strict.Spec.Rules = securityv1alpha1.PolicyRules{
		MaxCriticalCVEs:  ptr(int32(0)),
		MaxHighCVEs:      ptr(int32(0)),
		BlockMalware:     ptr(true),
		BlockSecrets:     ptr(true),
		BlockUnsafeModel: ptr(true),
		BlockModelDrift:  ptr(true),
	}

	eval := policy.Evaluate(
		[]securityv1alpha1.ScannerResult{result},
		securityv1alpha1.ArtifactRef{URI: "pvc://claim/m"},
		strict, nil, time.Now(),
	)

	t.Logf("under the strictest policy expressible: verdict=%s risk=%d violations=%d",
		eval.Verdict, eval.RiskScore, len(eval.Violations))

	if eval.Verdict != "Approved" {
		t.Errorf("this now blocks (verdict %q) — the limitation is closed and this test "+
			"should be replaced by one asserting the block", eval.Verdict)
	}
}

func ptr[T any](v T) *T { return &v }
