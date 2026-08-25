package audit

import (
	"fmt"
	"testing"
)

// chainOf builds n sealed records, returning them in order. The prefix keeps
// separate chains genuinely distinct: records are deterministic, so two chains
// built from the same inputs are the same chain, hashes included.
func chainOf(n int, prefix string) []Record {
	var out []Record
	var prev *Record
	for i := 0; i < n; i++ {
		r := Seal(Record{Type: EventVerdictIssued, Subject: fmt.Sprintf("%s/v%d", prefix, i)}, prev)
		out = append(out, r)
		prev = &out[len(out)-1]
	}
	return out
}

func anchorAt(records []Record, n int) *Anchor {
	return &Anchor{Length: uint64(n), Head: records[n-1].Hash, Location: "s3://bucket/audit"}
}

// The point of the whole exercise: a suffix verifies on its own when it is
// told what came before it.
func TestASuffixVerifiesAgainstItsAnchor(t *testing.T) {
	all := chainOf(50, "m")
	kept, anchor := all[20:], anchorAt(all, 20)

	if v := Verify(kept, nil); v.Valid {
		t.Error("a suffix verified as a whole chain: the verifier is not checking where it starts")
	}

	v := VerifyFrom(kept, anchor, nil)
	if !v.Valid {
		t.Fatalf("anchored suffix rejected: %v", v.Problems)
	}
	if v.Length != 50 {
		t.Errorf("length %d: an anchored chain is as long as the anchor plus what follows, so 50", v.Length)
	}
	if v.Anchored != 20 {
		t.Errorf("anchored %d, want 20", v.Anchored)
	}
	if v.Head != all[49].Hash {
		t.Error("head is not the last record's hash")
	}
}

// A checkpoint taken over the whole log still applies after the front of the
// log has been moved away. If it did not, archiving would cost the property
// the chain exists to provide.
func TestACheckpointOverTheWholeLogStillApplies(t *testing.T) {
	all := chainOf(50, "m")
	cp := Head(all)

	v := VerifyFrom(all[20:], anchorAt(all, 20), &cp)
	if !v.Valid {
		t.Fatalf("checkpoint rejected an intact archived chain: %v", v.Problems)
	}
}

// An anchor is trusted, so it must not be able to bless a chain it does not
// actually join onto.
func TestAnAnchorCannotLaunderADiscontinuity(t *testing.T) {
	all := chainOf(50, "m")
	other := chainOf(50, "unrelated")

	cases := []struct {
		name   string
		anchor *Anchor
		want   string
	}{
		{"head from a different chain",
			&Anchor{Length: 20, Head: other[19].Hash},
			"does not follow"},
		{"length short by one, so the first record is off by one",
			&Anchor{Length: 19, Head: all[19].Hash},
			"claims sequence"},
		{"length long by one",
			&Anchor{Length: 21, Head: all[19].Hash},
			"claims sequence"},
		{"genesis head at a nonzero length",
			&Anchor{Length: 20, Head: GenesisHash},
			"does not follow"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := VerifyFrom(all[20:], tc.anchor, nil)
			if v.Valid {
				t.Fatal("accepted: a bad anchor can pass off an unrelated or misaligned chain")
			}
			joined := fmt.Sprint(v.Problems)
			if !contains(joined, tc.want) {
				t.Errorf("problems do not explain the break (%q): %v", tc.want, v.Problems)
			}
		})
	}
}

// Dropping records from the middle of a retained suffix must still be caught.
func TestAGapInsideTheSuffixIsStillFound(t *testing.T) {
	all := chainOf(50, "m")
	gapped := append(append([]Record{}, all[20:30]...), all[31:]...)

	v := VerifyFrom(gapped, anchorAt(all, 20), nil)
	if v.Valid {
		t.Error("a record was removed from the middle of the retained chain and it verified")
	}
}

// A nil anchor has to behave exactly as before, or every existing caller
// changes meaning underneath.
func TestNoAnchorIsTheOldBehaviour(t *testing.T) {
	all := chainOf(12, "m")
	cp := Head(all)

	a, b := Verify(all, &cp), VerifyFrom(all, nil, &cp)
	if a.Valid != b.Valid || a.Length != b.Length || a.Head != b.Head || a.Anchored != 0 {
		t.Errorf("unanchored verify drifted: %+v vs %+v", a, b)
	}
	if !a.Valid {
		t.Fatalf("a whole chain stopped verifying: %v", a.Problems)
	}
}

func contains(hay, needle string) bool {
	return len(hay) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(hay); i++ {
			if hay[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
