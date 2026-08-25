// Package maintenance keeps the objects Cupel creates from growing without end.
//
// Everything here exists because of one omission: the operator wrote objects
// and never removed any. A cluster scanning two hundred model versions a week
// accumulates a scan and seven reports each time, which is tens of thousands of
// objects a year that no one asked for and nothing was going to clean up. None
// of it is a problem on the day it is installed, which is why it was missed.
package maintenance

import (
	"context"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
)

// DefaultMaxAge is how long a finished scan is kept before it is removed.
//
// Long enough that a quarterly review still finds what it is looking for, short
// enough that the object count settles instead of climbing. The decision itself
// outlives this: the verdict stays in the model's security report and the
// record of it stays in the audit chain. What ages out is the working detail of
// a scan whose conclusion has already been recorded elsewhere.
const DefaultMaxAge = 90 * 24 * time.Hour

// Maintenance deletes: the archiver removes audit records that have been
// written out of the cluster, and the pruner removes finished scans, which take
// their reports with them. Nothing else in Cupel deletes anything, so these are
// the only verbs that had no reason to exist until now.
//
// +kubebuilder:rbac:groups=security.davano.io,resources=auditrecords,verbs=delete
// +kubebuilder:rbac:groups=security.davano.io,resources=artifactscans,verbs=list;delete
// +kubebuilder:rbac:groups=security.davano.io,resources=modelsecurityreports,verbs=list

// Pruner removes finished scans, and with them the reports they own.
type Pruner struct {
	Client client.Client
	// Namespace to prune, or empty for all of them.
	Namespace string
	// MaxAge is how long a finished scan is kept. Zero means DefaultMaxAge;
	// negative means never prune.
	MaxAge time.Duration
	// Now is injectable for tests.
	Now func() time.Time
}

func (p *Pruner) maxAge() time.Duration {
	if p.MaxAge == 0 {
		return DefaultMaxAge
	}
	return p.MaxAge
}

func (p *Pruner) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// Run deletes scans that finished longer ago than MaxAge, and reports how many.
//
// Two things are never removed, whatever their age. A scan that has not
// finished is left alone, because an object that is still being worked on is
// not old, it is in progress. And a scan that a model's current security report
// points at is left alone regardless, because that report is what the admission
// gate reads: deleting the scan underneath it would take away the evidence for
// a verdict that is still in force.
func (p *Pruner) Run(ctx context.Context) (int, error) {
	if p.maxAge() < 0 {
		return 0, nil
	}

	var opts []client.ListOption
	if p.Namespace != "" {
		opts = append(opts, client.InNamespace(p.Namespace))
	}

	inUse, err := p.scansInUse(ctx, opts)
	if err != nil {
		return 0, err
	}

	var scans securityv1alpha1.ArtifactScanList
	if err := p.Client.List(ctx, &scans, opts...); err != nil {
		return 0, fmt.Errorf("list scans: %w", err)
	}

	cutoff := p.now().Add(-p.maxAge())
	deleted := 0
	for i := range scans.Items {
		scan := &scans.Items[i]
		if scan.Status.CompletionTime == nil {
			continue
		}
		if !scan.Status.CompletionTime.Time.Before(cutoff) {
			continue
		}
		if _, held := inUse[key{scan.Namespace, scan.Name}]; held {
			continue
		}
		// The scan owns its reports, so this takes them with it.
		if err := p.Client.Delete(ctx, scan); err != nil && !apierrors.IsNotFound(err) {
			return deleted, fmt.Errorf("delete scan %s/%s: %w", scan.Namespace, scan.Name, err)
		}
		deleted++
	}
	return deleted, nil
}

type key struct{ namespace, name string }

// scansInUse collects the scans that current model security reports point at.
func (p *Pruner) scansInUse(ctx context.Context, opts []client.ListOption) (map[key]struct{}, error) {
	var reports securityv1alpha1.ModelSecurityReportList
	if err := p.Client.List(ctx, &reports, opts...); err != nil {
		return nil, fmt.Errorf("list model security reports: %w", err)
	}
	inUse := make(map[key]struct{}, len(reports.Items))
	for _, r := range reports.Items {
		if r.Spec.ScanRef != "" {
			inUse[key{r.Namespace, r.Spec.ScanRef}] = struct{}{}
		}
	}
	return inUse, nil
}
