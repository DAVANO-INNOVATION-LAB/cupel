package audit

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/assay/api/v1alpha1"
)

// testScheme builds the scheme both helpers need.
func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := securityv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

func testRecorder(t *testing.T) *Recorder {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := securityv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return &Recorder{
		Client:    fake.NewClientBuilder().WithScheme(scheme).Build(),
		Namespace: "assay-system",
	}
}

func TestAppendBuildsAVerifiableChain(t *testing.T) {
	r := testRecorder(t)
	ctx := context.Background()

	if _, err := r.Append(ctx, RiskAccepted("fraud", "v3", "alice@davano.net", "compensating control", []string{"CVE-1"}, "sha256:abc")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Append(ctx, VerdictIssued("fraud", "v4", "Quarantined", 87, "sha256:def")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Append(ctx, DeploymentDecision("fraud", "v4", "prod", "Deployment/api", false, "quarantined")); err != nil {
		t.Fatal(err)
	}

	v, err := r.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !v.Valid {
		t.Fatalf("a freshly written chain must verify: %v", v.Problems)
	}
	if v.Length != 3 {
		t.Fatalf("want 3 records, got %d", v.Length)
	}
}

// The checkpoint must track the chain, or truncation stops being detectable.
func TestCheckpointFollowsTheChain(t *testing.T) {
	r := testRecorder(t)
	ctx := context.Background()

	for i := 0; i < 4; i++ {
		if _, err := r.Append(ctx, VerdictIssued("m", "v", "Approved", 0, "")); err != nil {
			t.Fatal(err)
		}
	}
	_, cp, err := r.Chain(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if cp == nil {
		t.Fatal("no checkpoint was published")
	}
	if cp.Length != 4 {
		t.Fatalf("checkpoint should record 4 records, got %d", cp.Length)
	}
}

// Deleting a record must be caught. This is the scenario the whole package
// exists for: somebody removing the record of a decision they made.
func TestDeletingARecordIsDetectedInCluster(t *testing.T) {
	r := testRecorder(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		if _, err := r.Append(ctx, RiskAccepted("m", "v", "bob", "because", nil, "")); err != nil {
			t.Fatal(err)
		}
	}

	// Remove the third record, as somebody covering their tracks would.
	var victim securityv1alpha1.AuditRecord
	key := client.ObjectKey{Name: recordName(3), Namespace: "assay-system"}
	if err := r.Client.Get(ctx, key, &victim); err != nil {
		t.Fatal(err)
	}
	if err := r.Client.Delete(ctx, &victim); err != nil {
		t.Fatal(err)
	}

	v, err := r.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v.Valid {
		t.Fatal("deleting an audit record must not verify")
	}
}

// Editing a record in place must be caught even though Kubernetes allowed the
// write — RBAC is the first line, the chain is the one that does not depend on
// RBAC being configured correctly.
func TestEditingARecordIsDetectedInCluster(t *testing.T) {
	r := testRecorder(t)
	ctx := context.Background()

	if _, err := r.Append(ctx, RiskAccepted("m", "v", "mallory", "looked fine", nil, "")); err != nil {
		t.Fatal(err)
	}

	var rec securityv1alpha1.AuditRecord
	key := client.ObjectKey{Name: recordName(1), Namespace: "assay-system"}
	if err := r.Client.Get(ctx, key, &rec); err != nil {
		t.Fatal(err)
	}
	rec.Spec.Actor = "alice"
	if err := r.Client.Update(ctx, &rec); err != nil {
		t.Fatal(err)
	}

	v, err := r.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v.Valid {
		t.Fatal("rewriting the actor on a record must not verify")
	}
}

func TestRecordsRoundTripThroughTheAPIShape(t *testing.T) {
	r := testRecorder(t)
	ctx := context.Background()

	original, err := r.Append(ctx, RiskAccepted("fraud", "v3", "alice", "reviewed", []string{"B", "A"}, "sha256:xyz"))
	if err != nil {
		t.Fatal(err)
	}

	records, _, err := r.Chain(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("want 1 record, got %d", len(records))
	}
	got := records[0]
	if got.Hash != original.Hash {
		t.Fatal("the hash did not survive storage; the chain would never verify")
	}
	if got.ComputeHash() != got.Hash {
		t.Fatal("a record read back from storage must still hash to its stored hash")
	}
	// Findings are sorted when recorded, so the same set in a different order
	// produces the same record rather than a spurious difference.
	if got.Detail["findings"] != "A,B" {
		t.Fatalf("findings should be sorted, got %q", got.Detail["findings"])
	}
}

func TestCheckpointRefusesToRegress(t *testing.T) {
	r := testRecorder(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if _, err := r.Append(ctx, VerdictIssued("m", "v", "Approved", 0, "")); err != nil {
			t.Fatal(err)
		}
	}
	// A shorter chain must not be allowed to re-bless the checkpoint.
	err := r.checkpoint(ctx, nil)
	if err == nil {
		t.Fatal("the checkpoint must refuse to move backwards, or truncation becomes re-blessable")
	}
}

// countingClient records how many List calls reach the API server.
//
// The point of the append rewrite is a cost, not a behaviour, and a cost is
// only pinned by counting it. Everything else in this file would pass equally
// well against the version that listed the whole chain on every write.
type countingClient struct {
	client.Client
	lists int
	gets  int
}

func (c *countingClient) List(ctx context.Context, l client.ObjectList, opts ...client.ListOption) error {
	c.lists++
	return c.Client.List(ctx, l, opts...)
}

func (c *countingClient) Get(ctx context.Context, key client.ObjectKey, o client.Object, opts ...client.GetOption) error {
	c.gets++
	return c.Client.Get(ctx, key, o, opts...)
}

// Appending to a long chain must not read the chain.
//
// This is the defect the rewrite closes: every append listed every AuditRecord
// in the namespace and sorted them, from an uncached client in the scan pod. The
// chain is append-only and nothing prunes it, so the cost of recording a
// decision grew with the number of decisions ever recorded.
func TestAppendDoesNotListTheWholeChain(t *testing.T) {
	scheme := testScheme(t)
	counting := &countingClient{Client: fake.NewClientBuilder().WithScheme(scheme).Build()}
	r := &Recorder{Client: counting, Namespace: "assay-system"}

	// Build a chain long enough that a listing would be obvious.
	for i := 0; i < 25; i++ {
		if _, err := r.Append(context.Background(), Record{
			Type: "scan", Subject: "m/v1", Actor: "test",
		}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	// Only the first append may list, and only because no checkpoint exists
	// yet. Every append after that has one to read.
	if counting.lists > 1 {
		t.Errorf("appending 25 records issued %d List calls; the chain should be "+
			"read at most once, when there is no checkpoint to read instead", counting.lists)
	}

	// And the chain must still be correct: sequential, linked, verifiable.
	records, cp, err := r.Chain(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 25 {
		t.Fatalf("chain holds %d records, want 25", len(records))
	}
	if v := Verify(records, cp); !v.Valid {
		t.Errorf("the chain no longer verifies after the rewrite: %+v", v)
	}
	for i, rec := range records {
		if rec.Seq != uint64(i+1) {
			t.Fatalf("record %d has seq %d; the chain is not sequential", i, rec.Seq)
		}
	}
}

// A checkpoint that has fallen behind must still yield the true head, or the
// next record would link to the wrong predecessor and break the chain.
func TestHeadCatchesUpFromAStaleCheckpoint(t *testing.T) {
	scheme := testScheme(t)
	r := &Recorder{
		Client:    fake.NewClientBuilder().WithScheme(scheme).Build(),
		Namespace: "assay-system",
	}
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if _, err := r.Append(ctx, Record{Type: "scan", Subject: "m/v1"}); err != nil {
			t.Fatal(err)
		}
	}

	// Roll the checkpoint back to record 2 and append again.
	if err := r.putCheckpoint(ctx, Checkpoint{Length: 2, Head: "stale"}); err != nil {
		// Regression is refused by design; write it directly instead.
		var cp securityv1alpha1.AuditCheckpoint
		if gerr := r.Client.Get(ctx, client.ObjectKey{
			Name: CheckpointName, Namespace: r.Namespace}, &cp); gerr != nil {
			t.Fatal(gerr)
		}
		cp.Spec.Length = 2
		if uerr := r.Client.Update(ctx, &cp); uerr != nil {
			t.Fatal(uerr)
		}
	}

	sealed, err := r.Append(ctx, Record{Type: "scan", Subject: "m/v2"})
	if err != nil {
		t.Fatalf("append after a stale checkpoint: %v", err)
	}
	if sealed.Seq != 6 {
		t.Errorf("new record has seq %d, want 6 — the walk did not catch up", sealed.Seq)
	}

	records, cp2, err := r.Chain(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v := Verify(records, cp2); !v.Valid {
		t.Errorf("chain broken after appending past a stale checkpoint: %+v", v)
	}
}
