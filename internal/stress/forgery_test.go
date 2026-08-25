//go:build stress

package stress

import (
	"fmt"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/audit"
)

// Two records that differ must never hash the same.
//
// The chain's whole guarantee is that a record cannot be changed without the
// hash changing. Every field is folded into one string with delimiters between
// them, so a field carrying a delimiter is the way that guarantee breaks: make
// one field's contents look like the start of the next and two different
// records collapse onto the same bytes.
func TestNoTwoDifferentRecordsShareACanonicalForm(t *testing.T) {
	base := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

	// Values chosen to attack the encoding: every delimiter, the escape
	// character itself, and the escape sequences the escaper produces.
	nasty := []string{
		"", "a", "a:b", "a;b", "a=b", "a\nb", `a\b`,
		`a\nb`, `a\cb`, `a\sb`, `a\eb`, `a\\b`,
		"\nsubject=other", "\nactor=root", "\nprev=" + audit.GenesisHash,
		"x;y:z=w", ":", ";", "=", "\n", `\`,
		"d\u00e9tail", "\u200b", "\ufeff",
	}

	seen := map[string]audit.Record{}
	checked := 0

	add := func(r audit.Record) {
		r.Hash = r.ComputeHash()
		canon := string(r.Canonical())
		checked++
		if prev, ok := seen[canon]; ok {
			if !sameRecord(prev, r) {
				t.Errorf("COLLISION: two different records share a canonical form\n"+
					"  a: %+v\n  b: %+v\n  canonical: %q", prev, r, canon)
			}
			return
		}
		seen[canon] = r
	}

	for _, s := range nasty {
		for _, a := range nasty {
			add(audit.Record{Seq: 1, Time: base, Type: audit.EventVerdictIssued,
				Subject: s, Actor: a, PrevHash: audit.GenesisHash})
		}
	}
	for _, k := range nasty {
		for _, v := range nasty {
			add(audit.Record{Seq: 1, Time: base, Type: audit.EventVerdictIssued,
				Subject: "m/v1", Actor: "system", PrevHash: audit.GenesisHash,
				Detail: map[string]string{k: v}})
			// Two entries, to attack the key/value and entry separators together.
			add(audit.Record{Seq: 1, Time: base, Type: audit.EventVerdictIssued,
				Subject: "m/v1", Actor: "system", PrevHash: audit.GenesisHash,
				Detail: map[string]string{k: v, "z": "1"}})
		}
	}
	// The type is written into the same stream. It is an internal enum today,
	// which is exactly the kind of assumption worth testing rather than
	// trusting.
	for _, s := range nasty {
		add(audit.Record{Seq: 1, Time: base, Type: audit.EventType(s),
			Subject: "m/v1", Actor: "system", PrevHash: audit.GenesisHash})
	}

	t.Logf("%d crafted records, %d distinct canonical forms", checked, len(seen))
}

func sameRecord(a, b audit.Record) bool {
	if a.Seq != b.Seq || !a.Time.Equal(b.Time) || a.Type != b.Type ||
		a.Subject != b.Subject || a.Actor != b.Actor || a.PrevHash != b.PrevHash ||
		len(a.Detail) != len(b.Detail) {
		return false
	}
	for k, v := range a.Detail {
		if b.Detail[k] != v {
			return false
		}
	}
	return true
}

// The same question asked by volume rather than by hand.
func TestRandomRecordsDoNotCollide(t *testing.T) {
	alphabet := []string{"a", "b", ":", ";", "=", "\n", `\`, "\\n", "\\c", ""}
	pick := func(r *rand.Rand, n int) string {
		out := ""
		for i := 0; i < n; i++ {
			out += alphabet[r.IntN(len(alphabet))]
		}
		return out
	}

	r := rand.New(rand.NewPCG(1, 2))
	base := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	seen := map[string]audit.Record{}

	const n = 200_000
	for i := 0; i < n; i++ {
		rec := audit.Record{
			Seq: 1, Time: base, Type: audit.EventVerdictIssued,
			Subject: pick(r, r.IntN(5)), Actor: pick(r, r.IntN(5)),
			PrevHash: audit.GenesisHash,
			Detail:   map[string]string{pick(r, r.IntN(4)): pick(r, r.IntN(4))},
		}
		canon := string(rec.Canonical())
		if prev, ok := seen[canon]; ok && !sameRecord(prev, rec) {
			t.Fatalf("COLLISION after %d records:\n  a: %+v\n  b: %+v\n  canonical: %q",
				i, prev, rec, canon)
		}
		seen[canon] = rec
	}
	t.Logf("%d random records, %d distinct canonical forms, no collisions", n, len(seen))
}

// A record's hash must cover its position, so a record cannot be replayed
// somewhere else in the chain.
func TestARecordCannotBeReplayedAtAnotherPosition(t *testing.T) {
	base := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	mk := func(seq uint64, prev string) audit.Record {
		r := audit.Record{Seq: seq, Time: base, Type: audit.EventDeploymentAdmitted,
			Subject: "m/v1", Actor: "system", PrevHash: prev}
		r.Hash = r.ComputeHash()
		return r
	}
	a := mk(5, audit.GenesisHash)
	b := mk(6, audit.GenesisHash)
	if a.Hash == b.Hash {
		t.Error("the same record at two positions hashes identically: it can be moved " +
			fmt.Sprintf("within the chain (%s)", a.Hash[:12]))
	}
	c := mk(5, "1111111111111111111111111111111111111111111111111111111111111111")
	if a.Hash == c.Hash {
		t.Error("the predecessor is not covered by the hash: a record can be re-parented")
	}
}
