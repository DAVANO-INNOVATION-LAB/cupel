package controller

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
)

func finished(name string, completedAgo time.Duration) *securityv1alpha1.ArtifactScan {
	t := metav1.NewTime(time.Now().Add(-completedAgo))
	return &securityv1alpha1.ArtifactScan{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: securityv1alpha1.ArtifactScanStatus{
			Phase:          "Completed",
			CompletionTime: &t,
			StartTime:      &t,
		},
	}
}

func TestRescanDueRespectsTheInterval(t *testing.T) {
	interval := &metav1.Duration{Duration: 5 * time.Minute}

	if due, _ := rescanDue(finished("recent", time.Minute), interval); due {
		t.Fatal("a scan one minute old must not be due for a five-minute rescan")
	}
	if due, _ := rescanDue(finished("old", 10*time.Minute), interval); !due {
		t.Fatal("a scan ten minutes old is due for a five-minute rescan")
	}
}

func TestRescanNotDueWithoutAnInterval(t *testing.T) {
	if due, _ := rescanDue(finished("old", 30*24*time.Hour), nil); due {
		t.Fatal("with no interval configured a version is scanned once and never revisited")
	}
	zero := &metav1.Duration{Duration: 0}
	if due, _ := rescanDue(finished("old", 30*24*time.Hour), zero); due {
		t.Fatal("a zero interval means no periodic rescan")
	}
}

// The regression this file exists for.
//
// Rescans are written under new names so earlier verdicts stay on the record.
// That means the ORIGINAL scan keeps its completion time forever. Ageing the
// interval against it makes every poll find a rescan due once the original
// passes the interval — one new scan and one new Job per poll, indefinitely.
// Observed live: 269 scans and 183 Jobs where about 15 were expected.
//
// The fix ages against the most recent scan, so this asserts the shape of the
// comparison rather than the plumbing.
func TestRescanAgesAgainstTheLatestScanNotTheFirst(t *testing.T) {
	interval := &metav1.Duration{Duration: 5 * time.Minute}

	// The original, long past the interval — this is what the old code checked.
	original := finished("scan-model-1", 80*time.Minute)
	// A rescan that ran a minute ago.
	newest := finished("scan-model-1-20260819-0039", time.Minute)

	if due, _ := rescanDue(original, interval); !due {
		t.Fatal("precondition: the original is old enough to look due")
	}
	if due, why := rescanDue(newest, interval); due {
		t.Fatalf("a rescan ran a minute ago, so nothing is due yet; got %q", why)
	}
}

func TestFinishedAfterOrdersByCompletion(t *testing.T) {
	older := finished("a", 10*time.Minute)
	newer := finished("b", time.Minute)

	if !finishedAfter(newer, older) {
		t.Fatal("the one that completed more recently should sort later")
	}
	if finishedAfter(older, newer) {
		t.Fatal("ordering must not be symmetric")
	}
}

// A scan with no completion time at all must not win the "latest" comparison,
// or an unfinished scan could suppress a rescan that is genuinely due.
func TestFinishedAfterHandlesMissingTimes(t *testing.T) {
	timed := finished("timed", time.Minute)
	untimed := &securityv1alpha1.ArtifactScan{
		ObjectMeta: metav1.ObjectMeta{Name: "untimed"},
		Status:     securityv1alpha1.ArtifactScanStatus{Phase: "Completed"},
	}

	if finishedAfter(untimed, timed) {
		t.Fatal("a scan with no timestamps cannot be the most recent")
	}
	if !finishedAfter(timed, untimed) {
		t.Fatal("a timestamped scan beats one with no timestamps")
	}
}

// Nothing finished yet means there is no age to measure. Treating that as due
// would start a second scan while the first is still running.
func TestRescanNotDueWhenNothingHasFinished(t *testing.T) {
	interval := &metav1.Duration{Duration: 5 * time.Minute}
	if due, _ := rescanDue(nil, interval); due {
		t.Fatal("with no finished scan there is nothing to age; a rescan must not fire")
	}
}

func TestRescanNotDueWhileScanIsRunning(t *testing.T) {
	running := &securityv1alpha1.ArtifactScan{
		ObjectMeta: metav1.ObjectMeta{Name: "running"},
		Status:     securityv1alpha1.ArtifactScanStatus{Phase: "Scanning"},
	}
	interval := &metav1.Duration{Duration: time.Nanosecond}
	if due, _ := rescanDue(running, interval); due {
		t.Fatal("a scan in flight must not trigger another")
	}
}
