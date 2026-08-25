package audit

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func fill(t *testing.T, r *Recorder, n int) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < n; i++ {
		if _, err := r.Append(ctx, Record{
			Type: EventVerdictIssued, Subject: fmt.Sprintf("m/v%d", i), Actor: "system",
		}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
}

// memSink is a Sink that records what it was asked to do, so the tests can
// make it fail in the specific ways a real one does.
type memSink struct {
	data     map[string][]byte
	failPut  bool
	failGet  bool
	corrupt  bool
	putCalls int
}

func newMemSink() *memSink { return &memSink{data: map[string][]byte{}} }

func (m *memSink) Put(_ context.Context, name string, data []byte) (string, error) {
	m.putCalls++
	if m.failPut {
		return "", errors.New("sink is down")
	}
	stored := append([]byte(nil), data...)
	if m.corrupt && len(stored) > 0 {
		stored[0] ^= 0xff
	}
	m.data[name] = stored
	return "mem://" + name, nil
}

func (m *memSink) Get(_ context.Context, name string) ([]byte, error) {
	if m.failGet {
		return nil, errors.New("sink is down")
	}
	b, ok := m.data[name]
	if !ok {
		return nil, errors.New("not found")
	}
	return b, nil
}

// The ordinary case: the chain outgrows the threshold, the front is moved out,
// and what is left still verifies as part of the same log.
func TestArchivingLeavesTheChainVerifiable(t *testing.T) {
	r := testRecorder(t)
	ctx := context.Background()
	fill(t, r, 60)

	sink := newMemSink()
	a := &Archiver{Recorder: r, Sink: sink, Threshold: 50, Retain: 10}

	n, err := a.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 50 {
		t.Fatalf("archived %d records, want 50", n)
	}

	records, cp, err := r.Chain(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 10 {
		t.Fatalf("%d records retained, want 10", len(records))
	}
	if cp.Archived == nil {
		t.Fatal("no archive boundary was published")
	}
	if cp.Archived.Length != 50 {
		t.Errorf("boundary at %d, want 50", cp.Archived.Length)
	}

	v := VerifyFrom(records, cp.Anchor(), cp)
	if !v.Valid {
		t.Fatalf("the retained chain does not verify against its boundary: %v", v.Problems)
	}
	if v.Length != 60 {
		t.Errorf("verified length %d: archived records still count toward the log", v.Length)
	}
}

// The archived segment has to be the records, exactly, or the archive is a
// story about the log rather than the log.
func TestTheArchivedSegmentRoundTripsToTheSameRecords(t *testing.T) {
	r := testRecorder(t)
	ctx := context.Background()
	fill(t, r, 30)

	original, _, err := r.Chain(ctx)
	if err != nil {
		t.Fatal(err)
	}

	sink := newMemSink()
	a := &Archiver{Recorder: r, Sink: sink, Threshold: 20, Retain: 5}
	if _, err := a.Run(ctx); err != nil {
		t.Fatal(err)
	}

	var stored []byte
	for _, v := range sink.data {
		stored = v
	}
	restored, err := DecodeSegment(stored)
	if err != nil {
		t.Fatal(err)
	}
	if len(restored) != 25 {
		t.Fatalf("segment holds %d records, want 25", len(restored))
	}
	for i, got := range restored {
		want := original[i]
		if got.Seq != want.Seq || got.Hash != want.Hash || got.PrevHash != want.PrevHash {
			t.Fatalf("record %d changed in the archive", i)
		}
		if got.ComputeHash() != got.Hash {
			t.Fatalf("record %d no longer hashes to its own hash after the round trip", got.Seq)
		}
	}
	if v := Verify(restored, nil); !v.Valid {
		t.Fatalf("the archived segment does not verify on its own: %v", v.Problems)
	}
}

// Every way the sink can fail must leave the records where they are. This is
// the one operation in the system that destroys evidence when it is wrong.
func TestNothingIsDeletedWhenTheArchiveCannotBeTrusted(t *testing.T) {
	cases := []struct {
		name   string
		break_ func(*memSink)
	}{
		{"the write fails", func(m *memSink) { m.failPut = true }},
		{"the write succeeds but cannot be read back", func(m *memSink) { m.failGet = true }},
		{"what comes back is not what went in", func(m *memSink) { m.corrupt = true }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := testRecorder(t)
			ctx := context.Background()
			fill(t, r, 60)

			sink := newMemSink()
			tc.break_(sink)
			a := &Archiver{Recorder: r, Sink: sink, Threshold: 50, Retain: 10}

			if _, err := a.Run(ctx); err == nil {
				t.Fatal("the archive failed and the run reported success")
			}

			records, cp, err := r.Chain(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if len(records) != 60 {
				t.Fatalf("%d records left after a failed archive: records were deleted "+
					"against an archive that could not be verified", len(records))
			}
			if cp.Anchor() != nil {
				t.Error("a boundary was published for an archive that did not succeed")
			}
			if v := Verify(records, cp); !v.Valid {
				t.Errorf("the chain was damaged by a failed archive: %v", v.Problems)
			}
		})
	}
}

// A run interrupted between publishing the boundary and deleting the records
// must be finishable, and must not look like a broken chain in the meantime.
func TestAnInterruptedRunIsFinishedByTheNextOne(t *testing.T) {
	r := testRecorder(t)
	ctx := context.Background()
	fill(t, r, 60)

	// Publish a boundary without deleting anything: exactly the state a crash
	// after putCheckpoint leaves behind.
	all, _, err := r.Chain(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sink := newMemSink()
	seg := all[:50]
	data, err := encodeSegment(seg)
	if err != nil {
		t.Fatal(err)
	}
	loc, err := sink.Put(ctx, SegmentName(seg[0].Seq, seg[49].Seq), data)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.putCheckpoint(ctx, Checkpoint{
		Length:   60,
		Head:     all[59].Hash,
		Archived: &Anchor{Length: 50, Head: seg[49].Hash, Location: loc},
	}); err != nil {
		t.Fatal(err)
	}

	// In the window, a reader must see a sound chain, not a broken one.
	records, cp, err := r.Chain(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 10 {
		t.Fatalf("reader saw %d records; the ones covered by the boundary should not be live", len(records))
	}
	if v := VerifyFrom(records, cp.Anchor(), cp); !v.Valid {
		t.Fatalf("an interrupted archive made the chain look broken: %v", v.Problems)
	}

	// The next run finishes the deletion without re-archiving.
	a := &Archiver{Recorder: r, Sink: sink, Threshold: 50, Retain: 10}
	if _, err := a.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if sink.putCalls != 1 {
		t.Errorf("sink written %d times: the interrupted segment was archived again", sink.putCalls)
	}

	remaining, err := r.load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 10 {
		t.Errorf("%d records still stored, want 10: the sweep did not finish the deletion", len(remaining))
	}
}

// Below the threshold, nothing happens. An archiver that runs eagerly would
// churn the log and the sink for no reason.
func TestBelowTheThresholdNothingMoves(t *testing.T) {
	r := testRecorder(t)
	ctx := context.Background()
	fill(t, r, 20)

	sink := newMemSink()
	a := &Archiver{Recorder: r, Sink: sink, Threshold: 50, Retain: 10}
	n, err := a.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("archived %d records below the threshold", n)
	}
	if sink.putCalls != 0 {
		t.Error("the sink was written to with nothing to archive")
	}
}

// Appending after an archive must continue the chain, not restart it.
func TestTheChainContinuesAfterAnArchive(t *testing.T) {
	r := testRecorder(t)
	ctx := context.Background()
	fill(t, r, 60)

	a := &Archiver{Recorder: r, Sink: newMemSink(), Threshold: 50, Retain: 10}
	if _, err := a.Run(ctx); err != nil {
		t.Fatal(err)
	}

	rec, err := r.Append(ctx, Record{Type: EventVerdictIssued, Subject: "after/v1"})
	if err != nil {
		t.Fatal(err)
	}
	if rec.Seq != 61 {
		t.Fatalf("the record after an archive got sequence %d, want 61", rec.Seq)
	}

	records, cp, err := r.Chain(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if cp.Anchor() == nil {
		t.Fatal("appending erased the archive boundary: every retained record is now orphaned")
	}
	if v := VerifyFrom(records, cp.Anchor(), cp); !v.Valid {
		t.Fatalf("the chain stopped verifying after an append following an archive: %v", v.Problems)
	}
}
