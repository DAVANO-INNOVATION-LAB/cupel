package audit

import (
	"os"
	"strings"
	"testing"
)

// The manager must not cache the audit chain. This is the one type whose size
// tracks uptime rather than workload, so caching it is an out-of-memory kill
// on a long-lived cluster — and the webhook shares the process, so the gate
// goes down with it.
func TestTheChainIsExcludedFromTheCache(t *testing.T) {
	opts := ClientOptions()
	if opts.Cache == nil {
		t.Fatal("client options do not configure the cache at all")
	}

	var kinds []string
	for _, obj := range opts.Cache.DisableFor {
		kinds = append(kinds, strings.TrimPrefix(
			strings.TrimPrefix(typeName(obj), "*"), "v1alpha1."))
	}

	for _, want := range []string{"AuditRecord", "AuditCheckpoint"} {
		found := false
		for _, k := range kinds {
			if strings.HasSuffix(k, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is cached: the manager's memory now grows with the "+
				"length of the audit chain (excluded: %v)", want, kinds)
		}
	}
}

// Excluding the types is only half of it — the manager has to actually apply
// the option. A cache policy nothing reads is the same as no policy.
func TestTheManagerAppliesTheCachePolicy(t *testing.T) {
	src, err := os.ReadFile("../../cmd/manager/main.go")
	if err != nil {
		t.Skipf("manager source not readable: %v", err)
	}
	if !strings.Contains(string(src), "audit.ClientOptions()") {
		t.Error("cmd/manager does not pass audit.ClientOptions() to the manager: " +
			"the audit chain is being cached again")
	}
}
