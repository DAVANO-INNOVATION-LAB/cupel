package maintenance

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// Maintenance is the only thing in Cupel that deletes, and a missing verb here
// fails in a way no other test can see: the fake client used everywhere else
// does not enforce RBAC, so archiving and retention pass their tests and then
// do nothing at all in a real cluster. The chain keeps growing, the object
// count keeps climbing, and the only symptom is a log line.
func TestTheDeleteVerbsAreGranted(t *testing.T) {
	for _, path := range []string{
		"../../config/rbac/role.yaml",
		"../../deploy/helm/cupel/rbac-rules.yaml",
	} {
		t.Run(path, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("cannot read the generated role: %v", err)
			}
			for _, resource := range []string{"auditrecords", "artifactscans"} {
				if !grants(string(data), resource, "delete") {
					t.Errorf("%s may not be deleted: the %s is a no-op in any real cluster",
						resource, map[string]string{
							"auditrecords":  "audit archive",
							"artifactscans": "scan retention",
						}[resource])
				}
			}
			// The pruner has to read the reports to know which scan a live
			// verdict rests on. Without list it cannot tell, and the safe
			// reading of that is to delete nothing.
			if !grants(string(data), "modelsecurityreports", "list") {
				t.Error("modelsecurityreports may not be listed: retention cannot tell " +
					"which scans are still in use")
			}
		})
	}
}

// grants reports whether a rule covering resource includes verb.
func grants(role, resource, verb string) bool {
	for _, block := range strings.Split(role, "- apiGroups:") {
		if !regexp.MustCompile(`(?m)^\s+- ` + resource + `\s*$`).MatchString(block) {
			continue
		}
		verbs := regexp.MustCompile(`verbs:\n((?:\s+- \w+\n)+)`).FindStringSubmatch(block)
		if verbs == nil {
			continue
		}
		for _, v := range strings.Fields(verbs[1]) {
			if strings.TrimPrefix(v, "- ") == verb {
				return true
			}
		}
	}
	return false
}
