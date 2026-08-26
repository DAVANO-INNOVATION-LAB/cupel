package naming

import (
	"fmt"
	"testing"
)

// Sanitizing an identifier throws information away, so distinct models used to
// derive one name — and whichever was written last decided what the other
// one's workloads were allowed to do. The fingerprint is what stops that.
func TestModelsThatSanitizeAlikeGetDifferentNames(t *testing.T) {
	inputs := [][2]string{
		{"acme/fraud", "v1"}, {"acme-fraud", "v1"}, {"acme.fraud", "v1"},
		{"Acme_Fraud", "v1"}, {"acme", "fraud-v1"}, {"ACME/FRAUD", "V1"},
		{"acme//fraud", "v1"}, {"acme fraud", "v1"}, {"a/b/c", "v1"},
		{"a-b-c", "v1"}, {"a.b.c", "v1"}, {"model", "v1.0"}, {"model", "v1-0"},
	}

	seen := map[string][2]string{}
	for _, in := range inputs {
		name := ModelReport(in[0], in[1])
		if prev, dup := seen[name]; dup {
			t.Errorf("COLLISION: (%q,%q) and (%q,%q) both derive %s",
				prev[0], prev[1], in[0], in[1], name)
		}
		seen[name] = in
		if len(name) > MaxNameLength {
			t.Errorf("%q is %d characters, over the DNS label limit", name, len(name))
		}
	}
	t.Logf("%d inputs that sanitize alike, %d distinct names", len(inputs), len(seen))
}

// The same at a scale no hand-written list reaches.
func TestNoCollisionsAcrossManyModels(t *testing.T) {
	seen := map[string]string{}
	sep := []string{"/", "-", ".", "_", " ", "//"}

	for i := 0; i < 4000; i++ {
		for _, s := range sep {
			model := fmt.Sprintf("team%d%smodel%d", i%40, s, i)
			key := model + "\x00v1"
			name := ModelReport(model, "v1")
			if prev, dup := seen[name]; dup && prev != key {
				t.Fatalf("COLLISION at %d: %q and %q both derive %s", i, prev, key, name)
			}
			seen[name] = key
		}
	}
	t.Logf("%d names, all distinct", len(seen))
}

// The old derivation has to stay exactly as it was: it is how a reader finds a
// report written before this change, and a reader that computes it differently
// finds nothing.
func TestTheLegacyDerivationIsUnchanged(t *testing.T) {
	cases := map[[2]string]string{
		{"detector", "v1"}:   "msr-detector-v1",
		{"acme/fraud", "v1"}: "msr-acme-fraud-v1",
		{"Acme_Fraud", "V1"}: "msr-acme-fraud-v1",
	}
	for in, want := range cases {
		if got := LegacyModelReport(in[0], in[1]); got != want {
			t.Errorf("LegacyModelReport(%q,%q) = %q, want %q", in[0], in[1], got, want)
		}
	}
}

// A reader must try both, and only both.
func TestBothNamesAreOfferedToAReader(t *testing.T) {
	names := func(m, v string) []string {
		out := []string{ModelReport(m, v)}
		if l := LegacyModelReport(m, v); l != out[0] {
			out = append(out, l)
		}
		return out
	}
	got := names("acme/fraud", "v1")
	if len(got) != 2 {
		t.Fatalf("a reader is offered %d names, want the current one and the legacy one", len(got))
	}
	if got[0] == got[1] {
		t.Error("both names are the same")
	}
}
