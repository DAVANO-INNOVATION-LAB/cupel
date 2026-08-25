package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/audit"
)

// splitPositional pulls the first bare argument out of an argument list,
// returning it and everything else in order.
func splitPositional(args []string) (string, []string) {
	// Only --checkpoint takes a value, and its value is a path, which looks
	// exactly like the directory we are hunting for.
	takesValue := map[string]bool{"-checkpoint": true, "--checkpoint": true}

	var positional string
	var rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			rest = append(rest, a)
			if !strings.Contains(a, "=") && takesValue[a] && i+1 < len(args) {
				i++
				rest = append(rest, args[i])
			}
			continue
		}
		if positional == "" {
			positional = a
			continue
		}
		rest = append(rest, a)
	}
	return positional, rest
}

// runAuditVerify checks an archived audit chain from the files alone.
//
// The chain outlives the cluster that produced it, and the person who most
// needs to check it — an auditor, a year later — has a directory of segments
// and no credentials. Everything this needs is in those files, apart from the
// checkpoint, which is optional and comes from wherever it was anchored: an
// evidence bundle, a ticket, an auditor's own records.
func runAuditVerify(args []string) int {
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	checkpointPath := fs.String("checkpoint", "",
		"JSON checkpoint to check the chain against, as published at the time")
	asJSON := fs.Bool("json", false, "emit the result as JSON")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `cupel audit verify <archive-dir> [flags]

Verifies an archived audit chain from its segment files.

  --checkpoint FILE   check against a checkpoint published at the time
  --json              emit the result as JSON
`)
	}
	// Go's flag package stops parsing at the first bare argument, so
	// "verify DIR --checkpoint F" would silently ignore the checkpoint and
	// report the weaker result as though it were the stronger one. Lift the
	// directory out first and let the flags come in either order.
	dir, rest := splitPositional(args)
	if err := fs.Parse(rest); err != nil {
		return exitError
	}
	if dir == "" || fs.NArg() != 0 {
		fs.Usage()
		return exitError
	}

	records, segments, err := audit.ReadArchive(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read the archive: %v\n", err)
		return exitError
	}
	if len(segments) == 0 {
		fmt.Fprintf(os.Stderr, "no audit segments in %s\n", dir)
		return exitError
	}

	var cp *audit.Checkpoint
	if *checkpointPath != "" {
		data, err := os.ReadFile(*checkpointPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot read the checkpoint: %v\n", err)
			return exitError
		}
		cp = &audit.Checkpoint{}
		if err := json.Unmarshal(data, cp); err != nil {
			fmt.Fprintf(os.Stderr, "cannot parse the checkpoint: %v\n", err)
			return exitError
		}
	}

	// An archive is the older part of a chain, not the whole of one. Handing it
	// the full checkpoint would compare 200 archived records against a log of
	// 260 and call the difference a truncation — reporting a correct archive as
	// evidence of tampering. What describes an archive is the anchor inside the
	// checkpoint, which says how far the archived part was meant to reach.
	v := audit.Verify(records, nil)
	if v.Valid && cp != nil {
		v.Problems = append(v.Problems, checkAgainstCheckpoint(records, v.Head, cp)...)
		v.Valid = len(v.Problems) == 0
	}

	if *asJSON {
		out, err := json.MarshalIndent(struct {
			Segments     []string           `json:"segments"`
			Verification audit.Verification `json:"verification"`
		}{segments, v}, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			return exitError
		}
		fmt.Println(string(out))
		if !v.Valid {
			return exitQuarantined
		}
		return exitApproved
	}

	fmt.Printf("archive   %s\n", dir)
	fmt.Printf("segments  %d\n", len(segments))
	fmt.Printf("records   %d (sequence %d through %d)\n",
		len(records), records[0].Seq, records[len(records)-1].Seq)
	fmt.Printf("head      %s\n", v.Head)

	if !v.Valid {
		fmt.Printf("\nThis archive does not verify:\n")
		for _, p := range v.Problems {
			fmt.Printf("  - %s\n", p)
		}
		return exitQuarantined
	}

	fmt.Printf("\n%d records verified. Every record follows the one before it and "+
		"still hashes to\nthe hash it carries.\n", len(records))

	switch {
	case cp == nil:
		// Say what has not been checked. Internal consistency is the weaker of
		// the two claims, and reading it as the stronger one is the mistake
		// this output exists to prevent.
		fmt.Printf("\nNo checkpoint was supplied, so this shows the archive is internally\n" +
			"consistent, not that it is complete. A chain with records removed from\n" +
			"the end verifies exactly like this one. Pass --checkpoint to settle it.\n")
	case cp.Archived != nil:
		fmt.Printf("\nThe checkpoint says %d records were archived and this archive holds %d\n"+
			"of them, ending where the checkpoint says they end. The remaining %d are\n"+
			"held in the cluster, and continue this chain.\n",
			cp.Archived.Length, len(records), cp.Length-cp.Archived.Length)
	default:
		fmt.Printf("\nThis matches the checkpoint at %d records, so nothing has been removed\n"+
			"from the end.\n", cp.Length)
	}
	return exitApproved
}

// checkAgainstCheckpoint compares an archive to what a checkpoint says about it.
//
// Two shapes are legitimate. If the checkpoint carries an archive boundary, the
// archive should be exactly that boundary: the same number of records, ending
// on the same hash. If it does not, the checkpoint describes a chain that was
// never split, and the archive should be the whole of it.
func checkAgainstCheckpoint(records []audit.Record, head string, cp *audit.Checkpoint) []string {
	var problems []string
	n := uint64(len(records))

	if a := cp.Archived; a != nil {
		if n != a.Length {
			problems = append(problems, fmt.Sprintf(
				"the checkpoint says %d records were archived, but this archive holds %d: "+
					"%d are missing from it", a.Length, n, int64(a.Length)-int64(n)))
		}
		if head != a.Head {
			problems = append(problems, fmt.Sprintf(
				"this archive ends on %s, but the checkpoint says the archived records "+
					"end on %s: it is not the archive this checkpoint describes",
				short(head), short(a.Head)))
		}
		return problems
	}

	switch {
	case n < cp.Length:
		problems = append(problems, fmt.Sprintf(
			"the checkpoint records a chain of %d and this archive holds %d, with no "+
				"archive boundary to account for the difference: %d records are unaccounted for",
			cp.Length, n, cp.Length-n))
	case n == cp.Length && head != cp.Head:
		problems = append(problems, fmt.Sprintf(
			"this archive has the checkpointed length but a different head (%s, the "+
				"checkpoint says %s): it has been rewritten", short(head), short(cp.Head)))
	}
	return problems
}

func short(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}
