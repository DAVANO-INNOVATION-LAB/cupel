package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/audit"
)

func archiveOf(n int) ([]audit.Record, string) {
	var out []audit.Record
	var prev *audit.Record
	for i := 0; i < n; i++ {
		r := audit.Seal(audit.Record{Type: audit.EventVerdictIssued, Subject: "m/v1"}, prev)
		out = append(out, r)
		prev = &out[len(out)-1]
	}
	return out, out[len(out)-1].Hash
}

// An archive is the older part of a chain, not a short chain. Comparing it
// against the whole log's length would report every correct archive as a
// truncation — the exact misreading this command exists to prevent.
func TestAnArchiveIsNotATruncatedChain(t *testing.T) {
	records, head := archiveOf(200)
	cp := &audit.Checkpoint{
		Length:   260,
		Head:     "whatever-the-live-head-is",
		Archived: &audit.Anchor{Length: 200, Head: head},
	}

	if problems := checkAgainstCheckpoint(records, head, cp); len(problems) != 0 {
		t.Fatalf("a correct archive was reported as a problem: %v", problems)
	}
}

func TestTheArchiveIsCheckedAgainstWhatTheCheckpointSaysOfIt(t *testing.T) {
	records, head := archiveOf(200)
	other, otherHead := archiveOf(200)
	_ = other

	cases := []struct {
		name    string
		records []audit.Record
		head    string
		cp      *audit.Checkpoint
		want    string
	}{
		{
			"records missing from the archive",
			records[:190], records[189].Hash,
			&audit.Checkpoint{Length: 260, Archived: &audit.Anchor{Length: 200, Head: head}},
			"10 are missing",
		},
		{
			"an archive that is not the one described",
			records, head,
			&audit.Checkpoint{Length: 260, Archived: &audit.Anchor{Length: 200, Head: "0011223344556677"}},
			"not the archive this checkpoint describes",
		},
		{
			"a whole chain shorter than its checkpoint, with no boundary to explain it",
			records[:150], records[149].Hash,
			&audit.Checkpoint{Length: 200, Head: head},
			"unaccounted for",
		},
		{
			"a whole chain of the right length but a different head",
			records, head,
			&audit.Checkpoint{Length: 200, Head: otherHead + "x"},
			"it has been rewritten",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			problems := checkAgainstCheckpoint(tc.records, tc.head, tc.cp)
			if len(problems) == 0 {
				t.Fatal("accepted")
			}
			if !strings.Contains(strings.Join(problems, " "), tc.want) {
				t.Errorf("problems do not explain it (%q): %v", tc.want, problems)
			}
		})
	}
}

// A checkpoint path looks exactly like the archive directory the command is
// looking for. Taking the wrong one silently drops the checkpoint and reports
// the weaker result as though it were the stronger one.
func TestFlagsAndTheDirectoryComeInEitherOrder(t *testing.T) {
	cases := []struct {
		args     []string
		wantDir  string
		wantRest []string
	}{
		{[]string{"/archive"}, "/archive", nil},
		{[]string{"/archive", "--checkpoint", "/cp.json"}, "/archive", []string{"--checkpoint", "/cp.json"}},
		{[]string{"--checkpoint", "/cp.json", "/archive"}, "/archive", []string{"--checkpoint", "/cp.json"}},
		{[]string{"--checkpoint=/cp.json", "/archive"}, "/archive", []string{"--checkpoint=/cp.json"}},
		{[]string{"--json", "/archive"}, "/archive", []string{"--json"}},
		{[]string{"/archive", "--json", "--checkpoint", "/cp.json"}, "/archive",
			[]string{"--json", "--checkpoint", "/cp.json"}},
	}

	for _, tc := range cases {
		dir, rest := splitPositional(tc.args)
		if dir != tc.wantDir {
			t.Errorf("%v: directory %q, want %q", tc.args, dir, tc.wantDir)
		}
		if !reflect.DeepEqual(rest, tc.wantRest) {
			t.Errorf("%v: flags %v, want %v", tc.args, rest, tc.wantRest)
		}
	}
}
