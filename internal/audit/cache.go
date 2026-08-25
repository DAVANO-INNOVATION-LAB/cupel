package audit

import (
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
)

// UncachedTypes lists the audit types that must never enter an informer cache.
//
// The chain is append-only and unbounded: it grows for as long as the cluster
// keeps scanning, and unlike scans and reports there is no natural point at
// which a record stops being interesting. Caching it makes the manager's
// resident memory a function of uptime rather than of workload, which is the
// shape of failure that arrives without warning and does not recover on its
// own.
//
// Nothing reconciles these types, so no watch is lost by excluding them, and
// the reads that remain are single Gets by computed name rather than lists.
func UncachedTypes() []client.Object {
	return []client.Object{
		&securityv1alpha1.AuditRecord{},
		&securityv1alpha1.AuditCheckpoint{},
	}
}

// ClientOptions returns the client configuration a manager must use so that
// appending to the chain does not accumulate in memory.
func ClientOptions() client.Options {
	return client.Options{Cache: &client.CacheOptions{DisableFor: UncachedTypes()}}
}

func typeName(obj client.Object) string {
	return fmt.Sprintf("%T", obj)
}
