package compliance

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Catalog is an indexed, ordered view of a framework's controls.
type Catalog struct {
	Framework Framework
	controls  []Control
	byID      map[string]Control
}

// NISTAIRMF returns the AI RMF 1.0 catalog.
func NISTAIRMF() *Catalog {
	c := &Catalog{
		Framework: NISTAIRMF10,
		controls:  append([]Control(nil), nistAIRMF10...),
		byID:      make(map[string]Control, len(nistAIRMF10)),
	}
	for _, ctrl := range c.controls {
		c.byID[ctrl.ID] = ctrl
	}
	sortControls(c.controls)
	return c
}

// Get returns a control by subcategory ID.
func (c *Catalog) Get(id string) (Control, error) {
	ctrl, ok := c.byID[id]
	if !ok {
		return Control{}, fmt.Errorf("unknown %s control %q", c.Framework, id)
	}
	return ctrl, nil
}

// Controls returns every control in AI RMF ordering.
func (c *Catalog) Controls() []Control {
	return append([]Control(nil), c.controls...)
}

// ByFunction returns the controls belonging to one core function.
func (c *Catalog) ByFunction(fn Function) []Control {
	var out []Control
	for _, ctrl := range c.controls {
		if ctrl.Function == fn {
			out = append(out, ctrl)
		}
	}
	return out
}

// Automatable returns the controls Cupel can evidence in full or in part.
func (c *Catalog) Automatable() []Control {
	var out []Control
	for _, ctrl := range c.controls {
		if ctrl.Automation != AutomationNone {
			out = append(out, ctrl)
		}
	}
	return out
}

// Coverage summarizes how much of the framework Cupel can evidence. It exists
// so the number can be stated plainly in a report rather than implied.
type Coverage struct {
	Total   int
	Full    int
	Partial int
	None    int
}

// Coverage computes the automation split across the catalog.
func (c *Catalog) Coverage() Coverage {
	cov := Coverage{Total: len(c.controls)}
	for _, ctrl := range c.controls {
		switch ctrl.Automation {
		case AutomationFull:
			cov.Full++
		case AutomationPartial:
			cov.Partial++
		default:
			cov.None++
		}
	}
	return cov
}

// String renders the coverage split for logs and report messages.
func (c Coverage) String() string {
	return fmt.Sprintf("%d controls: %d fully evidenceable, %d partial, %d attestation-only",
		c.Total, c.Full, c.Partial, c.None)
}

// Functions returns the four core functions in canonical order.
func Functions() []Function {
	return []Function{FunctionGovern, FunctionMap, FunctionMeasure, FunctionManage}
}

// functionOrder gives AI RMF's canonical function ordering, which is neither
// alphabetical nor the order the functions are usually recited in.
var functionOrder = map[Function]int{
	FunctionGovern: 0, FunctionMap: 1, FunctionMeasure: 2, FunctionManage: 3,
}

// sortControls orders by function, then numerically by category and
// subcategory, so "MEASURE 2.9" precedes "MEASURE 2.10" rather than following
// it as a string sort would.
func sortControls(controls []Control) {
	sort.SliceStable(controls, func(i, j int) bool {
		a, b := controls[i], controls[j]
		if functionOrder[a.Function] != functionOrder[b.Function] {
			return functionOrder[a.Function] < functionOrder[b.Function]
		}
		aMaj, aMin := splitID(a.ID)
		bMaj, bMin := splitID(b.ID)
		if aMaj != bMaj {
			return aMaj < bMaj
		}
		return aMin < bMin
	})
}

// splitID extracts the numeric category and subcategory from an identifier
// like "MEASURE 2.13".
func splitID(id string) (major, minor int) {
	_, numbers, ok := strings.Cut(id, " ")
	if !ok {
		return 0, 0
	}
	majorPart, minorPart, ok := strings.Cut(numbers, ".")
	if !ok {
		major, _ = strconv.Atoi(numbers)
		return major, 0
	}
	major, _ = strconv.Atoi(majorPart)
	minor, _ = strconv.Atoi(minorPart)
	return major, minor
}
