package audit

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
)

// CheckpointName is the singleton checkpoint object per namespace.
const CheckpointName = "cupel-audit-head"

// Recorder appends to the audit chain stored as AuditRecord objects.
type Recorder struct {
	Client    client.Client
	Namespace string
}

// Append seals an event onto the end of the chain and persists it.
//
// Concurrency is handled by the API server rather than by a lock: the record
// name embeds its sequence number, so two writers racing for the same position
// collide on AlreadyExists and the loser retries against the new head. That
// keeps the chain linear without the operator holding a lease it could lose.
func (r *Recorder) Append(ctx context.Context, event Record) (*Record, error) {
	const attempts = 5
	var lastErr error

	prev, err := r.head(ctx)
	if err != nil {
		return nil, err
	}

	for i := 0; i < attempts; i++ {
		sealed := Seal(event, prev)
		obj := &securityv1alpha1.AuditRecord{
			ObjectMeta: metav1.ObjectMeta{
				Name:      recordName(sealed.Seq),
				Namespace: r.Namespace,
				Labels: map[string]string{
					"security.davano.io/audit-type": string(sealed.Type),
				},
			},
			Spec: securityv1alpha1.AuditRecordSpec{
				Seq:      int64(sealed.Seq),
				Time:     metav1.NewTime(sealed.Time),
				Type:     string(sealed.Type),
				Subject:  sealed.Subject,
				Actor:    sealed.Actor,
				Detail:   sealed.Detail,
				PrevHash: sealed.PrevHash,
				Hash:     sealed.Hash,
			},
		}

		err = r.Client.Create(ctx, obj)
		if err == nil {
			// Advance the checkpoint. A failure here leaves a correct chain
			// with a stale checkpoint, which is a detectable inconsistency
			// rather than a silent gap, so it does not fail the append.
			//
			// The checkpoint also *is* the index: the next writer reads it to
			// find the head instead of listing the chain, so keeping it current
			// is what holds the append cost flat.
			_ = r.writeCheckpoint(ctx, sealed)
			return &sealed, nil
		}
		if !apierrors.IsAlreadyExists(err) {
			return nil, fmt.Errorf("append audit record: %w", err)
		}
		// Another writer took this position. Read *that* record — one Get by a
		// name we can compute — and build on it, rather than re-reading the
		// whole chain to discover what we already know the shape of.
		lastErr = err
		taken, terr := r.recordAt(ctx, sealed.Seq)
		if terr != nil {
			return nil, fmt.Errorf("append audit record: lost the head and could not read it back: %w", terr)
		}
		prev = taken
	}
	return nil, fmt.Errorf("append audit record: lost %d races for the chain head: %w", attempts, lastErr)
}

// load reads the chain in sequence order.
func (r *Recorder) load(ctx context.Context) ([]Record, error) {
	var list securityv1alpha1.AuditRecordList
	if err := r.Client.List(ctx, &list, client.InNamespace(r.Namespace)); err != nil {
		return nil, fmt.Errorf("list audit records: %w", err)
	}
	records := make([]Record, 0, len(list.Items))
	for _, item := range list.Items {
		records = append(records, fromAPI(item))
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Seq < records[j].Seq })
	return records, nil
}

// Chain returns the stored chain and its published checkpoint.
func (r *Recorder) Chain(ctx context.Context) ([]Record, *Checkpoint, error) {
	records, err := r.load(ctx)
	if err != nil {
		return nil, nil, err
	}

	var cpObj securityv1alpha1.AuditCheckpoint
	err = r.Client.Get(ctx, client.ObjectKey{Name: CheckpointName, Namespace: r.Namespace}, &cpObj)
	switch {
	case apierrors.IsNotFound(err):
		return records, nil, nil
	case err != nil:
		return nil, nil, err
	}
	cp := checkpointFromAPI(cpObj)

	// Drop anything the archive boundary already covers.
	//
	// Archiving publishes the boundary before deleting the records it covers,
	// so that an interrupted run leaves the records present rather than lost.
	// The cost is a window where the store holds records that the log no longer
	// counts as live. Returning them would make a chain that is exactly right
	// look like one that starts in the wrong place.
	if a := cp.Anchor(); a != nil && a.Length > 0 {
		kept := records[:0]
		for _, rec := range records {
			if rec.Seq > a.Length {
				kept = append(kept, rec)
			}
		}
		records = kept
	}
	return records, cp, nil
}

// readCheckpoint reads the published checkpoint, or nil when there is none.
func (r *Recorder) readCheckpoint(ctx context.Context) (*Checkpoint, error) {
	var obj securityv1alpha1.AuditCheckpoint
	err := r.Client.Get(ctx, client.ObjectKey{Name: CheckpointName, Namespace: r.Namespace}, &obj)
	switch {
	case apierrors.IsNotFound(err):
		return nil, nil
	case err != nil:
		return nil, err
	}
	return checkpointFromAPI(obj), nil
}

// Size reports the length of the chain and how much of it is still stored,
// without reading the records.
//
// Both numbers are in the checkpoint already, which matters because the caller
// is usually asking in order to watch for growth: listing tens of thousands of
// records every time somebody wants to know how many there are would be its own
// small version of the problem being measured.
func (r *Recorder) Size(ctx context.Context) (length, retained uint64, err error) {
	var cpObj securityv1alpha1.AuditCheckpoint
	err = r.Client.Get(ctx, client.ObjectKey{Name: CheckpointName, Namespace: r.Namespace}, &cpObj)
	switch {
	case apierrors.IsNotFound(err):
		// No checkpoint yet means no appends yet, or a chain written by
		// something that never published one. Counting is the only honest
		// answer, and at this point there is nothing much to count.
		records, err := r.load(ctx)
		if err != nil {
			return 0, 0, err
		}
		return uint64(len(records)), uint64(len(records)), nil
	case err != nil:
		return 0, 0, err
	}
	length = uint64(cpObj.Spec.Length)
	retained = length - uint64(cpObj.Spec.ArchivedLength)
	return length, retained, nil
}

// Verify checks the stored chain against its published checkpoint.
func (r *Recorder) Verify(ctx context.Context) (Verification, error) {
	records, cp, err := r.Chain(ctx)
	if err != nil {
		return Verification{}, err
	}
	return Verify(records, cp), nil
}

// checkpoint publishes the new head, given the whole chain.
func (r *Recorder) checkpoint(ctx context.Context, records []Record) error {
	return r.putCheckpoint(ctx, Head(records))
}

// putCheckpoint publishes a head that has already been computed.
func (r *Recorder) putCheckpoint(ctx context.Context, cp Checkpoint) error {
	obj := &securityv1alpha1.AuditCheckpoint{
		ObjectMeta: metav1.ObjectMeta{Name: CheckpointName, Namespace: r.Namespace},
		Spec:       specFromCheckpoint(cp),
	}

	var existing securityv1alpha1.AuditCheckpoint
	err := r.Client.Get(ctx, client.ObjectKey{Name: CheckpointName, Namespace: r.Namespace}, &existing)
	switch {
	case apierrors.IsNotFound(err):
		return r.Client.Create(ctx, obj)
	case err != nil:
		return err
	}
	// Never move a checkpoint backwards. A checkpoint that can regress is not
	// a checkpoint: it would let a truncated log be re-blessed.
	if existing.Spec.Length > obj.Spec.Length {
		return fmt.Errorf("refusing to regress the checkpoint from %d to %d records",
			existing.Spec.Length, obj.Spec.Length)
	}
	// The same rule for the archive boundary, and for the same reason. Moving
	// it backwards would claim records are still in the cluster after they have
	// been deleted from it, which is exactly what a truncation looks like.
	if existing.Spec.ArchivedLength > obj.Spec.ArchivedLength && obj.Spec.ArchivedLength > 0 {
		return fmt.Errorf("refusing to regress the archive boundary from %d to %d records",
			existing.Spec.ArchivedLength, obj.Spec.ArchivedLength)
	}
	// An ordinary append knows the head but nothing about archiving, so it
	// leaves these fields empty. Taking them at face value would erase the
	// boundary and strand every retained record: they would appear to start
	// partway through a chain with nothing to say why.
	if obj.Spec.ArchivedLength == 0 {
		obj.Spec.ArchivedLength = existing.Spec.ArchivedLength
		obj.Spec.ArchivedHead = existing.Spec.ArchivedHead
		obj.Spec.ArchiveLocation = existing.Spec.ArchiveLocation
	}
	existing.Spec = obj.Spec
	return r.Client.Update(ctx, &existing)
}

func checkpointFromAPI(obj securityv1alpha1.AuditCheckpoint) *Checkpoint {
	cp := &Checkpoint{
		Length: uint64(obj.Spec.Length),
		Head:   obj.Spec.Head,
		Time:   obj.Spec.Time.Time,
	}
	if obj.Spec.ArchivedLength > 0 {
		cp.Archived = &Anchor{
			Length:   uint64(obj.Spec.ArchivedLength),
			Head:     obj.Spec.ArchivedHead,
			Location: obj.Spec.ArchiveLocation,
		}
	}
	return cp
}

func specFromCheckpoint(cp Checkpoint) securityv1alpha1.AuditCheckpointSpec {
	spec := securityv1alpha1.AuditCheckpointSpec{
		Length: int64(cp.Length),
		Head:   cp.Head,
		Time:   metav1.NewTime(cp.Time),
	}
	if cp.Archived != nil {
		spec.ArchivedLength = int64(cp.Archived.Length)
		spec.ArchivedHead = cp.Archived.Head
		spec.ArchiveLocation = cp.Archived.Location
	}
	return spec
}

func fromAPI(item securityv1alpha1.AuditRecord) Record {
	return Record{
		Seq:      uint64(item.Spec.Seq),
		Time:     item.Spec.Time.Time.UTC(),
		Type:     EventType(item.Spec.Type),
		Subject:  item.Spec.Subject,
		Actor:    item.Spec.Actor,
		Detail:   item.Spec.Detail,
		PrevHash: item.Spec.PrevHash,
		Hash:     item.Spec.Hash,
	}
}

func recordName(seq uint64) string {
	return fmt.Sprintf("audit-%012d", seq)
}

// Subject formats a model and version as an audit subject.
func Subject(model, version string) string {
	if version == "" {
		return model
	}
	return model + "/" + version
}

// RiskAccepted builds the record for an accepted risk.
func RiskAccepted(model, version, actor, reason string, findings []string, digest string) Record {
	detail := map[string]string{"reason": reason}
	if len(findings) > 0 {
		sorted := append([]string{}, findings...)
		sort.Strings(sorted)
		detail["findings"] = strings.Join(sorted, ",")
	}
	// The digest binds the acceptance to the bytes that were reviewed. Without
	// it the record says a risk was accepted for a name, and names get reused.
	if digest != "" {
		detail["digest"] = digest
	}
	return Record{
		Time:    time.Now().UTC(),
		Type:    EventRiskAccepted,
		Subject: Subject(model, version),
		Actor:   actor,
		Detail:  detail,
	}
}

// VerdictIssued builds the record for a scan reaching a verdict.
func VerdictIssued(model, version, verdict string, risk int32, digest string) Record {
	detail := map[string]string{
		"verdict": verdict,
		"risk":    fmt.Sprintf("%d", risk),
	}
	if digest != "" {
		detail["digest"] = digest
	}
	return Record{
		Time:    time.Now().UTC(),
		Type:    EventVerdictIssued,
		Subject: Subject(model, version),
		Actor:   "system",
		Detail:  detail,
	}
}

// DeploymentDecision builds the record for an admission decision.
func DeploymentDecision(model, version, namespace, workload string, admitted bool, why string) Record {
	t := EventDeploymentBlocked
	if admitted {
		t = EventDeploymentAdmitted
	}
	return Record{
		Time:    time.Now().UTC(),
		Type:    t,
		Subject: Subject(model, version),
		Actor:   "system",
		Detail: map[string]string{
			"namespace": namespace,
			"workload":  workload,
			"reason":    why,
		},
	}
}

// PromotionDecision builds the record for a promotion request that reached a
// terminal state.
//
// The verdict the decision was taken against is carried in the detail rather
// than left to be looked up later. A promotion is only defensible in relation
// to what was known at the time, and the ModelSecurityReport it referred to is
// mutable — by the time anyone reads this record, the verdict it names may no
// longer be the one the model has.
func PromotionDecision(model, version, environment, phase, decidedBy, verdict, why string) Record {
	t := EventModelPromoted
	if phase != "Approved" {
		t = EventPromotionRefused
	}
	actor := decidedBy
	if actor == "" {
		// Nobody decided: the security verdict did. Recording "system" here
		// rather than an empty actor keeps the distinction legible.
		actor = "system"
	}
	return Record{
		Time:    time.Now().UTC(),
		Type:    t,
		Subject: Subject(model, version),
		Actor:   actor,
		Detail: map[string]string{
			"environment": environment,
			"phase":       phase,
			"verdict":     verdict,
			"reason":      why,
		},
	}
}

// head finds the last record in the chain without reading the chain.
//
// This is the difference between an append that costs one read and one that
// costs the whole log. The old path listed every AuditRecord in the namespace on
// every append, sorted them in memory, and took the last — from an uncached
// client in the scan pod, so a cluster with fifty thousand audit records did a
// fifty-thousand-object read every time a scan finished. The chain is
// append-only and nothing prunes it, so that cost only ever grew.
//
// The checkpoint already stored what Seal needs: the sequence number of the head
// and its hash. Reading it is one Get. Records written since the checkpoint are
// found by walking forward from there — by name, since a record's name is a pure
// function of its sequence number — which is normally a single miss.
//
// The full listing survives as the cold path for a chain that has no checkpoint
// yet, which is a chain with almost nothing in it.
func (r *Recorder) head(ctx context.Context) (*Record, error) {
	var cp securityv1alpha1.AuditCheckpoint
	err := r.Client.Get(ctx, client.ObjectKey{Name: CheckpointName, Namespace: r.Namespace}, &cp)
	switch {
	case apierrors.IsNotFound(err):
		// No checkpoint: either an empty chain or one written before
		// checkpointing existed. Fall back to reading it, once.
		records, lerr := r.load(ctx)
		if lerr != nil {
			return nil, lerr
		}
		if len(records) == 0 {
			return nil, nil
		}
		return &records[len(records)-1], nil
	case err != nil:
		return nil, fmt.Errorf("read audit checkpoint: %w", err)
	}

	prev, err := r.recordAt(ctx, uint64(cp.Spec.Length))
	if err != nil {
		return nil, err
	}

	// Walk forward over anything appended since the checkpoint was last
	// written. Bounded so a checkpoint that has fallen badly behind degrades
	// into a slow append rather than an unbounded scan.
	const maxCatchUp = 1000
	for i := 0; i < maxCatchUp; i++ {
		next, err := r.recordAt(ctx, uint64(cp.Spec.Length)+uint64(i)+1)
		if err != nil {
			return nil, err
		}
		if next == nil {
			break
		}
		prev = next
	}
	return prev, nil
}

// recordAt reads one record by sequence number, returning nil when there is
// none. A record's name is derived from its sequence, so this needs no search.
func (r *Recorder) recordAt(ctx context.Context, seq uint64) (*Record, error) {
	if seq == 0 {
		return nil, nil
	}
	var obj securityv1alpha1.AuditRecord
	err := r.Client.Get(ctx, client.ObjectKey{
		Name: recordName(seq), Namespace: r.Namespace,
	}, &obj)
	switch {
	case apierrors.IsNotFound(err):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("read audit record %d: %w", seq, err)
	}
	rec := fromAPI(obj)
	return &rec, nil
}

// writeCheckpoint advances the published head to a single record.
//
// Takes the record rather than the whole chain: the checkpoint commits to the
// head and the length, and both are readable from the record that just became
// the head. Passing the chain was what forced the caller to hold it.
func (r *Recorder) writeCheckpoint(ctx context.Context, head Record) error {
	return r.putCheckpoint(ctx, Checkpoint{
		Length: head.Seq,
		Head:   head.Hash,
		Time:   head.Time,
	})
}
