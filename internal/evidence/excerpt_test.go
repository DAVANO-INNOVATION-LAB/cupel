package evidence

import (
	"testing"

	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/audit"
)

// A model's audit entries are scattered through a log it shares with every
// other model in the cluster. Asking whether those scattered entries form a
// chain is the wrong question, and answering it made every bundle for every
// model but the first report its own audit trail as tampered with.
func TestABundleForALateModelStillVerifies(t *testing.T) {
	in := sampleInput()

	b, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}

	if !b.Audit.Present {
		t.Fatal("this subject has records in the chain; the bundle says it has none")
	}
	if got := len(b.Audit.Records); got != 3 {
		t.Fatalf("excerpt has %d records, want the subject's 3", got)
	}
	for _, r := range b.Audit.Records {
		if r.Subject != "fraud/v3" {
			t.Fatalf("excerpt leaked another subject's record: %q", r.Subject)
		}
	}
	if b.Audit.Records[0].Seq == 1 {
		t.Fatal("fixture no longer exercises the bug: this subject's first record " +
			"is also the chain's first record")
	}
	if b.Audit.ChainLength != 6 {
		t.Errorf("chain length %d: the bundle should report the whole log's length, not the excerpt's",
			b.Audit.ChainLength)
	}

	v, err := Verify(b)
	if err != nil {
		t.Fatal(err)
	}
	if !v.Valid {
		t.Fatalf("an intact bundle reported itself invalid: %v", v.Problems)
	}
	if !v.RecordsIntact || !v.ChainValid {
		t.Fatalf("recordsIntact=%v chainValid=%v", v.RecordsIntact, v.ChainValid)
	}
}

// The bundle must carry the whole log's verdict, not a verdict recomputed from
// the excerpt — so a broken chain elsewhere in the log still reaches the reader.
func TestABrokenChainElsewhereStillReachesTheReader(t *testing.T) {
	in := sampleInput()
	// Break a record belonging to a different subject entirely.
	in.AuditChain[0].Actor = "tampered"

	b, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	if b.Audit.ChainValid {
		t.Fatal("the log was tampered with and the bundle reports the chain as sound")
	}
	if len(b.Audit.ChainProblems) == 0 {
		t.Fatal("the chain is reported invalid with nothing said about why")
	}

	v, _ := Verify(b)
	if v.Valid {
		t.Fatal("a bundle drawn from a tampered log must not verify")
	}
	// The subject's own entries are untouched, and the bundle should say so
	// rather than blaming them.
	if !v.RecordsIntact {
		t.Error("this subject's records were not touched; they should still be intact")
	}
}

// An archived chain still verifies: that is the whole point of the anchor.
func TestABundleVerifiesOverAnArchivedChain(t *testing.T) {
	in := sampleInput()
	whole := in.AuditChain
	cp := audit.Head(whole)

	// Pretend the first two records were archived out of the cluster.
	in.AuditChain = whole[2:]
	in.AuditAnchor = &audit.Anchor{
		Length: 2, Head: whole[1].Hash, Location: "s3://evidence/audit/0000000001-0000000002.jsonl",
	}
	in.AuditCheckpoint = &cp

	b, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	if !b.Audit.ChainValid {
		t.Fatalf("an archived chain failed to verify against its anchor: %v", b.Audit.ChainProblems)
	}
	if b.Audit.ChainLength != 6 {
		t.Errorf("chain length %d: archived records still count toward the log's length", b.Audit.ChainLength)
	}
	if b.Audit.Anchor == nil || b.Audit.Anchor.Location == "" {
		t.Error("the bundle does not tell a reader where the rest of the chain went")
	}

	v, _ := Verify(b)
	if !v.Valid {
		t.Fatalf("bundle over an archived chain reported invalid: %v", v.Problems)
	}
}
