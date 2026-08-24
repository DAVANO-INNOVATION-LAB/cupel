package controller

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/provenance"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/scanners"
)

func TestRenderTrustPolicyFlattensPublishers(t *testing.T) {
	publishers := []securityv1alpha1.TrustedPublisher{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "gha"},
			Spec: securityv1alpha1.TrustedPublisherSpec{
				DisplayName: "GitHub Actions",
				KeylessIdentity: &securityv1alpha1.KeylessIdentity{
					Issuer:  "https://token.actions.githubusercontent.com",
					Subject: "https://github.com/davano/*",
				},
				URIPrefixes: []string{"oci://ghcr.io/davano/"},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "onprem"},
			Spec: securityv1alpha1.TrustedPublisherSpec{
				CosignPublicKey: "-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----",
			},
		},
	}

	policy := RenderTrustPolicy(publishers, "/trust/root.json", true)
	if len(policy.Publishers) != 2 {
		t.Fatalf("want 2 publishers, got %d", len(policy.Publishers))
	}
	if policy.TrustRootPath != "/trust/root.json" || !policy.RequireTransparencyLog {
		t.Fatal("trust root and transparency-log requirement must survive rendering")
	}
	if !policy.Publishers[0].Keyless() {
		t.Fatal("the keyless publisher lost its identity")
	}
}

// A publisher with neither a key nor an identity can verify nothing. Counting
// it would let a cluster believe it has trust configured when it does not.
func TestRenderTrustPolicyDropsUnusablePublishers(t *testing.T) {
	publishers := []securityv1alpha1.TrustedPublisher{
		{ObjectMeta: metav1.ObjectMeta{Name: "empty"}},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "half"},
			// An issuer with no subject cannot pin an identity.
			Spec: securityv1alpha1.TrustedPublisherSpec{
				KeylessIdentity: &securityv1alpha1.KeylessIdentity{Issuer: "https://issuer"},
			},
		},
	}
	policy := RenderTrustPolicy(publishers, "", false)
	if len(policy.Publishers) != 0 {
		t.Fatalf("unusable publishers must be dropped, got %+v", policy.Publishers)
	}
	if policy.Trusted() {
		t.Fatal("a policy of unusable publishers must not report itself as trusted")
	}
}

func TestSyncTrustPolicyWritesConfigMap(t *testing.T) {
	scheme := digestTestScheme(t)
	tp := &securityv1alpha1.TrustedPublisher{
		ObjectMeta: metav1.ObjectMeta{Name: "gha", Namespace: "cupel-system"},
		Spec: securityv1alpha1.TrustedPublisherSpec{
			KeylessIdentity: &securityv1alpha1.KeylessIdentity{
				Issuer:  "https://token.actions.githubusercontent.com",
				Subject: "https://github.com/davano/cupel/.github/workflows/release.yml@refs/heads/main",
			},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tp).Build()

	if err := SyncTrustPolicy(context.Background(), c, "cupel-system", "/trust/root.json", true); err != nil {
		t.Fatal(err)
	}

	var cm corev1.ConfigMap
	key := client.ObjectKey{Namespace: "cupel-system", Name: TrustPolicyConfigMap}
	if err := c.Get(context.Background(), key, &cm); err != nil {
		t.Fatalf("the trust ConfigMap was not created: %v", err)
	}

	var policy provenance.Policy
	if err := json.Unmarshal([]byte(cm.Data[TrustPolicyKey]), &policy); err != nil {
		t.Fatalf("rendered policy is not valid JSON: %v", err)
	}
	if len(policy.Publishers) != 1 || policy.Publishers[0].Name != "gha" {
		t.Fatalf("publisher did not survive the round trip: %+v", policy.Publishers)
	}

	// A private key must never reach a scan pod. Only public material belongs
	// in a ConfigMap, which is readable by anything that can read the namespace.
	if strings.Contains(cm.Data[TrustPolicyKey], "PRIVATE KEY") {
		t.Fatal("the rendered trust policy must never contain private key material")
	}
}

func TestSyncTrustPolicyIsIdempotent(t *testing.T) {
	scheme := digestTestScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if err := SyncTrustPolicy(ctx, c, "cupel-system", "", false); err != nil {
			t.Fatalf("sync %d failed: %v", i, err)
		}
	}
	var list corev1.ConfigMapList
	if err := c.List(ctx, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("repeated syncs must not create duplicates, got %d", len(list.Items))
	}
}

// The provenance scanner is useless without its trust material, so the Job must
// actually mount it. This is the wiring that a unit test of the verifier alone
// would never catch.
func TestProvenanceJobMountsTrustPolicy(t *testing.T) {
	scan := &securityv1alpha1.ArtifactScan{
		ObjectMeta: metav1.ObjectMeta{Name: "s1", Namespace: "cupel-system"},
		Spec: securityv1alpha1.ArtifactScanSpec{
			ModelName: "m", ModelVersion: "1",
			Artifact: securityv1alpha1.ArtifactRef{URI: "s3://bucket/model"},
		},
	}
	def, err := scanners.Get("provenance")
	if err != nil {
		t.Fatal(err)
	}
	job, err := buildScanJob(scan, def, nil, JobConfig{OperatorImage: "cupel:test"})
	if err != nil {
		t.Fatal(err)
	}

	var scanContainer *corev1.Container
	for i := range job.Spec.Template.Spec.InitContainers {
		if job.Spec.Template.Spec.InitContainers[i].Name == "scan" {
			scanContainer = &job.Spec.Template.Spec.InitContainers[i]
		}
	}
	if scanContainer == nil {
		t.Fatal("no scan container")
	}

	var mounted bool
	for _, m := range scanContainer.VolumeMounts {
		if m.MountPath == TrustPolicyMountPath {
			mounted = true
			if !m.ReadOnly {
				t.Fatal("trust material must be mounted read-only")
			}
		}
	}
	if !mounted {
		t.Fatalf("the provenance scanner did not receive its trust policy; mounts: %+v",
			scanContainer.VolumeMounts)
	}

	// The placeholder must be substituted, or the runner looks for a file
	// literally named "$(TRUST_POLICY)" and silently verifies nothing.
	args := strings.Join(scanContainer.Args, " ")
	if strings.Contains(args, scanners.PlaceholderTrustPolicy) {
		t.Fatalf("trust policy placeholder was not substituted: %s", args)
	}
	if !strings.Contains(args, TrustPolicyMountPath) {
		t.Fatalf("args do not reference the mounted trust policy: %s", args)
	}
}

// A scanner that is not provenance has no business holding trust material.
func TestNonProvenanceJobDoesNotMountTrustPolicy(t *testing.T) {
	scan := &securityv1alpha1.ArtifactScan{
		ObjectMeta: metav1.ObjectMeta{Name: "s1", Namespace: "cupel-system"},
		Spec: securityv1alpha1.ArtifactScanSpec{
			ModelName: "m", ModelVersion: "1",
			Artifact: securityv1alpha1.ArtifactRef{URI: "s3://bucket/model"},
		},
	}
	def, err := scanners.Get("model-inspector")
	if err != nil {
		t.Fatal(err)
	}
	job, err := buildScanJob(scan, def, nil, JobConfig{OperatorImage: "cupel:test"})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range job.Spec.Template.Spec.Volumes {
		if v.Name == "trust-policy" {
			t.Fatal("only the provenance scanner should receive trust material")
		}
	}
}
