// Command reportname prints the ModelSecurityReport object name for a model
// version.
//
// The conformance script needs to plant a report the admission gate will
// actually find, and the gate looks reports up strictly by derived name
// (internal/naming.ModelReport, a fingerprinted flattening of the identity).
// Deriving it here rather than reimplementing the scheme in shell is the point:
// a second implementation would drift from this one silently, and the symptom
// would be a conformance run that passes because the gate found no report and
// admitted — which is the exact failure the script exists to catch.
//
//	go run ./hack/reportname <model> <version>
package main

import (
	"fmt"
	"os"

	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/naming"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: reportname <model> <version>")
		os.Exit(2)
	}
	fmt.Println(naming.ModelReport(os.Args[1], os.Args[2]))
}
