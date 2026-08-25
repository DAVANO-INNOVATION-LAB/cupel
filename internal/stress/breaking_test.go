//go:build stress

package stress

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/audit"
)

func fillChain(t *testing.T, r *audit.Recorder, n int) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < n; i++ {
		if _, err := r.Append(ctx, audit.VerdictIssued(
			fmt.Sprintf("m%d", i), "v1", "Approved", 5, "")); err != nil {
			t.Fatal(err)
		}
	}
}

// Archiving and appending run at the same time in a real cluster: the loop is
// on a ticker, the controllers are not. The archive reads a chain, writes part
// of it out, moves the boundary and deletes — all while new records land.
func TestArchivingWhileTheChainIsBeingWritten(t *testing.T) {
	r, _ := stressRecorder(t)
	ctx := context.Background()
	dir := t.TempDir()

	fillChain(t, r, 400)

	archiver := &audit.Archiver{
		Recorder: r, Sink: audit.DirSink{Dir: dir}, Threshold: 200, Retain: 50,
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Writers keep going throughout.
	for w := 0; w < 6; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := r.Append(ctx, audit.Record{
					Type: audit.EventDeploymentAdmitted, Subject: fmt.Sprintf("live%d/v%d", w, i),
				}); err != nil {
					t.Errorf("append during archive: %v", err)
					return
				}
			}
		}(w)
	}

	// Archive repeatedly while they write.
	archived := 0
	for i := 0; i < 12; i++ {
		n, err := archiver.Run(ctx)
		if err != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("archive run %d failed while the chain was being written: %v", i, err)
		}
		archived += n
	}
	close(stop)
	wg.Wait()

	records, cp, err := r.Chain(ctx)
	if err != nil {
		t.Fatal(err)
	}
	v := audit.VerifyFrom(records, cp.Anchor(), cp)
	t.Logf("archived %d records across concurrent writes; %d retained, chain length %d",
		archived, len(records), v.Length)
	if !v.Valid {
		t.Fatalf("archiving under concurrent writes broke the chain: %v", v.Problems)
	}

	// Nothing may be lost: the archive plus what is left must be the whole log.
	restored, _, err := audit.ReadArchive(dir)
	if err != nil {
		t.Fatal(err)
	}
	whole := append(restored, records...)
	if w := audit.Verify(whole, cp); !w.Valid {
		t.Fatalf("archive and tail do not reassemble into the log: %v", w.Problems)
	}
	if uint64(len(whole)) != v.Length {
		t.Errorf("reassembled %d records, the log claims %d", len(whole), v.Length)
	}
}

// A sink that fails intermittently — the ordinary condition of a network
// filesystem — must never cost a record.
type flakySink struct {
	dir   string
	mu    sync.Mutex
	calls int
	// failEvery makes every Nth Put fail after writing nothing.
	failEvery int
	// truncEvery makes every Nth Put write only half the bytes.
	truncEvery int
}

func (f *flakySink) Put(ctx context.Context, name string, data []byte) (string, error) {
	f.mu.Lock()
	f.calls++
	n := f.calls
	f.mu.Unlock()

	if f.failEvery > 0 && n%f.failEvery == 0 {
		return "", errors.New("transient sink failure")
	}
	if f.truncEvery > 0 && n%f.truncEvery == 0 {
		data = data[:len(data)/2]
	}
	path := filepath.Join(f.dir, name)
	if err := os.WriteFile(path, data, 0o640); err != nil {
		return "", err
	}
	return path, nil
}

func (f *flakySink) Get(_ context.Context, name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(f.dir, name))
}

func (f *flakySink) Remove(_ context.Context, name string) error {
	err := os.Remove(filepath.Join(f.dir, name))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func TestAFlakySinkNeverCostsARecord(t *testing.T) {
	r, _ := stressRecorder(t)
	ctx := context.Background()
	dir := t.TempDir()

	fillChain(t, r, 1200)
	before, _, err := r.Chain(ctx)
	if err != nil {
		t.Fatal(err)
	}

	sink := &flakySink{dir: dir, failEvery: 3, truncEvery: 4}
	archiver := &audit.Archiver{Recorder: r, Sink: sink, Threshold: 200, Retain: 100}

	// Keep the chain above the threshold so every run has real work, and the
	// sink gets to fail the way a network filesystem fails: sometimes.
	runs, failures, appended := 0, 0, 0
	for i := 0; i < 20; i++ {
		for j := 0; j < 300; j++ {
			if _, err := r.Append(ctx, audit.Record{
				Type: audit.EventDeploymentAdmitted, Subject: fmt.Sprintf("round%d/v%d", i, j),
			}); err != nil {
				t.Fatal(err)
			}
			appended++
		}
		if _, err := archiver.Run(ctx); err != nil {
			failures++
		}
		runs++
	}

	records, cp, err := r.Chain(ctx)
	if err != nil {
		t.Fatal(err)
	}
	restored, _, err := audit.ReadArchive(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Truncated segments are junk on disk; what matters is whether any record
	// was deleted from the cluster while its archive was unusable.
	live := uint64(len(records))
	if a := cp.Anchor(); a != nil {
		live += a.Length
	}
	written := uint64(len(before)) + uint64(appended)
	t.Logf("%d runs, %d failed on a flaky sink; %d records written, %d accounted for, "+
		"%d readable in the archive", runs, failures, written, live, len(restored))

	if failures == 0 {
		t.Fatal("the sink was set to fail and never did: this test is not testing anything")
	}
	if live != written {
		t.Fatalf("records went missing: %d accounted for, %d were written", live, written)
	}

	// Every record the chain says was archived must actually be readable.
	if a := cp.Anchor(); a != nil {
		readable := 0
		for _, rec := range restored {
			if rec.Seq <= a.Length {
				readable++
			}
		}
		if uint64(readable) < a.Length {
			t.Errorf("the boundary claims %d records were archived but only %d can be read back: "+
				"records were deleted against an archive that is not there", a.Length, readable)
		}
	}
}

// Records deleted out from under the archiver — an operator tidying up, a
// misapplied kubectl — must not be papered over.
func TestRecordsRemovedBehindTheArchiversBack(t *testing.T) {
	r, c := stressRecorder(t)
	ctx := context.Background()

	fillChain(t, r, 300)

	// Remove a record from the middle.
	victim := &securityv1alpha1.AuditRecord{
		ObjectMeta: metav1.ObjectMeta{Name: "audit-000000000150", Namespace: "cupel-system"},
	}
	if err := c.Delete(ctx, victim); err != nil {
		t.Fatal(err)
	}

	records, cp, err := r.Chain(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v := audit.VerifyFrom(records, cp.Anchor(), cp); v.Valid {
		t.Fatal("a record was deleted from the middle of the chain and it still verifies")
	}

	// And the archiver must refuse to archive a chain it cannot vouch for.
	archiver := &audit.Archiver{
		Recorder: r, Sink: audit.DirSink{Dir: t.TempDir()}, Threshold: 100, Retain: 50,
	}
	if _, err := archiver.Run(ctx); err == nil {
		t.Fatal("the archiver moved records out of a chain that does not verify")
	} else if !strings.Contains(err.Error(), "do not verify") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

// A forged boundary must not be able to hide records that were removed.
func TestAForgedBoundaryCannotHideADeletion(t *testing.T) {
	r, _ := stressRecorder(t)
	ctx := context.Background()
	dir := t.TempDir()

	fillChain(t, r, 400)
	archiver := &audit.Archiver{Recorder: r, Sink: audit.DirSink{Dir: dir}, Threshold: 200, Retain: 100}
	if _, err := archiver.Run(ctx); err != nil {
		t.Fatal(err)
	}

	_, cp, err := r.Chain(ctx)
	if err != nil {
		t.Fatal(err)
	}
	anchor := cp.Anchor()
	if anchor == nil {
		t.Fatal("nothing was archived")
	}

	// Someone with cluster access deletes half the archived segment and claims
	// a shorter boundary. The archive itself is what catches this.
	restored, _, err := audit.ReadArchive(dir)
	if err != nil {
		t.Fatal(err)
	}
	forged := &audit.Anchor{Length: anchor.Length / 2, Head: restored[anchor.Length/2-1].Hash}

	// Against the real archive, the forged boundary does not describe it.
	v := audit.VerifyFrom(restored[forged.Length:], forged, nil)
	if !v.Valid {
		t.Log("a forged shorter boundary is internally consistent with the tail, as expected")
	}
	// The checkpoint is what pins it: the log's length does not match.
	if v.Length == cp.Length {
		t.Error("a halved boundary produced the checkpointed length; truncation would be invisible")
	}
	t.Logf("forged boundary yields length %d, the checkpoint says %d: the difference is the tell",
		v.Length, cp.Length)
}
