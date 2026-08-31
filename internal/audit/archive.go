package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
)

// Sink is where archived segments are written.
//
// Get exists so a segment can be read back before the records it holds are
// deleted from the cluster. An archive that has not been read is a claim, not
// a copy, and deleting against a claim is how logs get lost.
type Sink interface {
	Put(ctx context.Context, name string, data []byte) (location string, err error)
	Get(ctx context.Context, name string) ([]byte, error)
}

// remover is implemented by sinks that can delete a segment again.
//
// A segment that fails its read-back is junk, and it will never become
// anything else. Left in place it is worse than absent: the records it should
// hold are still safe in the cluster, but every later read of the archive trips
// over the damaged file, so a transient write failure turns into an archive
// that permanently will not verify.
type remover interface {
	Remove(ctx context.Context, name string) error
}

// discard removes a segment that could not be trusted, and says so if it
// cannot. Failing to clean up does not fail the run: the records are still in
// the cluster either way, which is the property that matters.
func discard(ctx context.Context, sink Sink, name string) error {
	r, ok := sink.(remover)
	if !ok {
		return nil
	}
	return r.Remove(ctx, name)
}

// DirSink writes segments to a directory.
//
// A mounted volume is the one destination that works everywhere the product
// claims to run, an air-gapped enclave included. Object storage can be layered
// behind the same interface without the archiver knowing.
type DirSink struct{ Dir string }

func (d DirSink) Put(_ context.Context, name string, data []byte) (string, error) {
	if err := os.MkdirAll(d.Dir, 0o750); err != nil {
		return "", err
	}
	path := filepath.Join(d.Dir, name)
	// Write to a neighbour and rename, so a crash mid-write cannot leave a
	// truncated segment sitting where a complete one is expected.
	tmp := path + ".partial"
	// 0600: an archived segment is audit evidence read back by this process
	// alone. Nothing else in the pod needs it, so nothing else is given it.
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	return path, nil
}

func (d DirSink) Get(_ context.Context, name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(d.Dir, name))
}

// Remove deletes a segment. Used only to clean up one that failed its
// read-back; nothing removes a segment that verified.
func (d DirSink) Remove(_ context.Context, name string) error {
	err := os.Remove(filepath.Join(d.Dir, name))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// Archiver moves the front of the chain out of the cluster.
//
// The chain is the one thing here that grows for as long as the cluster runs,
// and nothing about a correct system ever stops it. Archiving keeps what is
// stored proportional to recent activity while leaving the log itself intact:
// the records are not discarded, they are moved, and the checkpoint records
// where they went so the chain still verifies end to end.
type Archiver struct {
	Recorder *Recorder
	Sink     Sink
	// Threshold is how many retained records trigger a run. Zero means
	// DefaultThreshold.
	Threshold int
	// Retain is how many recent records stay in the cluster after a run. Zero
	// means DefaultRetain.
	Retain int
}

// Defaults sized against the cluster's own limits rather than a round number.
//
// etcd's default backend quota is 2 GB and an audit record costs roughly 626
// bytes stored, so the log alone can take the whole cluster read-only somewhere
// near 1.7 million records. Archiving at 50,000 keeps the chain under three
// percent of that ceiling, which leaves room for a failing archive to go
// unnoticed for a long time without becoming anyone's outage.
const (
	DefaultThreshold = 50_000
	DefaultRetain    = 10_000
)

func (a *Archiver) threshold() int {
	if a.Threshold > 0 {
		return a.Threshold
	}
	return DefaultThreshold
}

func (a *Archiver) retain() int {
	if a.Retain > 0 {
		return a.Retain
	}
	return DefaultRetain
}

// SegmentName is the file a run of records is written to.
func SegmentName(first, last uint64) string {
	return fmt.Sprintf("audit-%012d-%012d.jsonl", first, last)
}

// Run archives the front of the retained chain if it has grown past the
// threshold, and reports how many records were moved.
//
// The order of operations is the whole safety argument. The segment is written,
// read back, and verified before the checkpoint moves, and the records are
// deleted only after the checkpoint says where they went. A crash at any point
// leaves either records that are still in the cluster and merely duplicated in
// the archive, or a boundary that the next run's sweep finishes acting on.
// Nothing in the sequence can lose a record.
func (a *Archiver) Run(ctx context.Context) (int, error) {
	// Finish any deletion a previous run did not get to, before anything else.
	// Until that is clear the boundary and the stored records disagree, and the
	// disagreement is invisible: the reader already hides records below the
	// boundary, so the only symptom is storage that never goes down.
	if err := a.sweep(ctx); err != nil {
		return 0, err
	}

	// Ask how big the chain is before reading it. Most runs have nothing to do,
	// and listing every record hourly to find that out would be a steady cost
	// paid for no result — on the very type this exists to keep small.
	_, retained, err := a.Recorder.Size(ctx)
	if err != nil {
		return 0, fmt.Errorf("measure chain: %w", err)
	}
	if retained <= uint64(a.threshold()) {
		return 0, nil
	}

	records, cp, err := a.Recorder.Chain(ctx)
	if err != nil {
		return 0, fmt.Errorf("read chain: %w", err)
	}

	if len(records) <= a.threshold() {
		return 0, nil
	}

	cut := len(records) - a.retain()
	if cut <= 0 {
		return 0, nil
	}
	segment := records[:cut]

	// Never archive a segment that does not verify. Moving records out of the
	// cluster is the point of no return for anyone inspecting them by hand, so
	// it happens only over a stretch of chain known to be sound.
	anchor := cp.Anchor()
	if v := VerifyFrom(segment, anchor, nil); !v.Valid {
		return 0, fmt.Errorf("refusing to archive: the records to be moved do not verify: %v", v.Problems)
	}

	data, err := encodeSegment(segment)
	if err != nil {
		return 0, err
	}
	name := SegmentName(segment[0].Seq, segment[len(segment)-1].Seq)

	location, err := a.Sink.Put(ctx, name, data)
	if err != nil {
		return 0, fmt.Errorf("write segment %s: %w", name, err)
	}

	// Read it back before trusting it. A sink that accepted the bytes and did
	// not keep them is indistinguishable from one that did, right up until the
	// records have been deleted and someone needs them.
	readBack, err := a.Sink.Get(ctx, name)
	if err != nil {
		return 0, a.reject(ctx, name, fmt.Errorf("segment %s was written but cannot be read back: %w", name, err))
	}
	if !bytes.Equal(readBack, data) {
		return 0, a.reject(ctx, name, fmt.Errorf(
			"segment %s reads back differently than it was written; not deleting anything", name))
	}
	restored, err := DecodeSegment(readBack)
	if err != nil {
		return 0, a.reject(ctx, name, fmt.Errorf("segment %s does not parse after the round trip: %w", name, err))
	}
	if v := VerifyFrom(restored, anchor, nil); !v.Valid {
		return 0, a.reject(ctx, name, fmt.Errorf(
			"segment %s does not verify after the round trip: %v", name, v.Problems))
	}

	// Publish the boundary before deleting. If the process stops here, the
	// records are still in the cluster and the next run's sweep removes them.
	//
	// Only the boundary moves. The head belongs to whatever is appending, which
	// is still appending: writing a whole checkpoint here would carry a head
	// that is already stale and be refused as a regression.
	last := segment[len(segment)-1]
	if err := a.Recorder.advanceBoundary(ctx, Anchor{
		Length:   last.Seq,
		Head:     last.Hash,
		Location: location,
	}); err != nil {
		return 0, err
	}

	deleted, err := a.deleteThrough(ctx, segment[0].Seq, last.Seq)
	if err != nil {
		return deleted, fmt.Errorf("delete archived records: %w", err)
	}
	return deleted, nil
}

// reject discards a segment that could not be trusted and returns why.
func (a *Archiver) reject(ctx context.Context, name string, cause error) error {
	if err := discard(ctx, a.Sink, name); err != nil {
		return fmt.Errorf("%w (and the unusable segment could not be removed: %w)", cause, err)
	}
	return cause
}

// sweep deletes records already covered by a published boundary, which is what
// a run interrupted between publishing and deleting leaves behind.
//
// The common case is that there is nothing to do, and it has to stay cheap:
// this runs every hour for the life of the cluster. Deletion goes in sequence
// order, so if the last covered record is gone the pass finished, and one Get
// settles it. Only when it is still there does anything list.
func (a *Archiver) sweep(ctx context.Context) error {
	cp, err := a.Recorder.readCheckpoint(ctx)
	if err != nil {
		return fmt.Errorf("read checkpoint: %w", err)
	}
	anchor := cp.Anchor()
	if anchor == nil || anchor.Length == 0 {
		return nil
	}

	var last securityv1alpha1.AuditRecord
	err = a.Recorder.Client.Get(ctx, client.ObjectKey{
		Name: recordName(anchor.Length), Namespace: a.Recorder.Namespace,
	}, &last)
	switch {
	case apierrors.IsNotFound(err):
		return nil // the previous pass finished
	case err != nil:
		return err
	}

	// Delete what is actually there rather than walking the whole range: after
	// a partial pass most of the range is already gone, and blindly issuing a
	// delete per sequence number would mean millions of calls that do nothing.
	stored, err := a.Recorder.load(ctx)
	if err != nil {
		return err
	}
	for _, rec := range stored {
		if rec.Seq > anchor.Length {
			continue
		}
		obj := &securityv1alpha1.AuditRecord{
			ObjectMeta: metav1.ObjectMeta{
				Name: recordName(rec.Seq), Namespace: a.Recorder.Namespace,
			},
		}
		if err := a.Recorder.Client.Delete(ctx, obj); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

// deleteThrough removes records in [first, last] by their computed names.
// Records already gone are not an error: the operation has to be repeatable
// for an interrupted run to be able to finish.
func (a *Archiver) deleteThrough(ctx context.Context, first, last uint64) (int, error) {
	deleted := 0
	for seq := first; seq <= last; seq++ {
		obj := &securityv1alpha1.AuditRecord{
			ObjectMeta: metav1.ObjectMeta{
				Name:      recordName(seq),
				Namespace: a.Recorder.Namespace,
			},
		}
		err := a.Recorder.Client.Delete(ctx, obj)
		switch {
		case err == nil:
			deleted++
		case apierrors.IsNotFound(err):
		default:
			return deleted, err
		}
	}
	return deleted, nil
}

func encodeSegment(records []Record) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, r := range records {
		if err := enc.Encode(r); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// ReadArchive reads every segment in a directory, in sequence order, and
// returns the records together with the segment names they came from.
//
// This is the auditor's path: a directory of segments and nothing else — no
// cluster, no network, no credentials. The archive has to be checkable by
// somebody who has only the archive.
func ReadArchive(dir string) ([]Record, []string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".jsonl") {
			names = append(names, e.Name())
		}
	}
	// Segment names lead with a zero-padded first sequence number, so sorting
	// them lexically is sorting them by position in the chain.
	sort.Strings(names)

	var out []Record
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, names, fmt.Errorf("read %s: %w", name, err)
		}
		records, err := DecodeSegment(data)
		if err != nil {
			return nil, names, fmt.Errorf("parse %s: %w", name, err)
		}
		out = append(out, records...)
	}
	return out, names, nil
}

// DecodeSegment parses a segment written by the archiver.
func DecodeSegment(data []byte) ([]Record, error) {
	var out []Record
	dec := json.NewDecoder(bytes.NewReader(data))
	for dec.More() {
		var r Record
		if err := dec.Decode(&r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}
