package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"github.com/bulwark-docker/bulwark/internal/store"
	"github.com/bulwark-docker/bulwark/pkg/types"
)

// queueDeps lets tests inject an open store.
type queueDeps struct {
	Store *store.Store
}

// cmdQueue dispatches `bulwark queue <subcommand>`. Subcommands:
//
//	list     show pending REVIEW updates and recorded decisions
//	approve  record an approval for the latest pending update on a container
//	reject   record a rejection
//	forget   remove a single decision
//	clear    remove all decisions (next scan re-notifies everything)
func cmdQueue(args []string, stdout, stderr io.Writer) error {
	return cmdQueueWith(args, stdout, stderr, queueDeps{})
}

func cmdQueueWith(args []string, stdout, stderr io.Writer, deps queueDeps) error {
	if len(args) == 0 {
		printQueueUsage(stderr)
		return errUsage
	}
	switch args[0] {
	case "-h", "--help", "help":
		printQueueUsage(stdout)
		return nil
	case "list":
		return cmdQueueList(args[1:], stdout, stderr, deps)
	case "approve":
		return cmdQueueDecision(args[1:], stdout, stderr, deps, store.DecisionApproved)
	case "reject":
		return cmdQueueDecision(args[1:], stdout, stderr, deps, store.DecisionRejected)
	case "forget":
		return cmdQueueForget(args[1:], stdout, stderr, deps)
	case "clear":
		return cmdQueueClear(args[1:], stdout, stderr, deps)
	default:
		fmt.Fprintf(stderr, "unknown queue subcommand: %s\n\n", args[0])
		printQueueUsage(stderr)
		return errUsage
	}
}

func printQueueUsage(w io.Writer) {
	fmt.Fprintln(w, `Usage: bulwark queue <subcommand> [flags]

Inspect and act on the approval queue. Decisions silence notifications
about a specific (container, image-digest) pair forever — the next
distinct registry digest re-opens the question.

Subcommands:
  list     Show pending REVIEW updates and recorded decisions
  approve  Mark a container's latest pending update as approved
  reject   Mark a container's latest pending update as rejected
  forget   Remove a single decision (re-opens the question)
  clear    Remove all decisions (next scan re-notifies everything)

Common flags: --data-dir <path>, --json (where supported).

Run "bulwark queue <subcommand> --help" for command-specific options.`)
}

// openQueueStore is the same flag-handling pattern used by `bulwark history`.
func openQueueStore(fs *flag.FlagSet, deps queueDeps) (*store.Store, func(), error) {
	if deps.Store != nil {
		return deps.Store, func() {}, nil
	}
	dataDir := fs.Lookup("data-dir").Value.String()
	if dataDir == "" {
		dataDir = os.Getenv("BULWARK_DATA_DIR")
	}
	if dataDir == "" {
		return nil, nil, errors.New("queue: --data-dir is required (or set BULWARK_DATA_DIR)")
	}
	st, err := store.Open(dataDir)
	if err != nil {
		return nil, nil, err
	}
	return st, func() { _ = st.Close() }, nil
}

// queueRow is the merged "pending review + decisions" view used by `list`.
type queueRow struct {
	Container      string `json:"container"`
	Image          string `json:"image,omitempty"`
	Level          string `json:"level,omitempty"`
	From           string `json:"from,omitempty"`
	To             string `json:"to,omitempty"`
	RegistryDigest string `json:"registry_digest,omitempty"`
	Decision       string `json:"decision"`
	DecidedBy      string `json:"decided_by,omitempty"`
	DecidedAt      string `json:"decided_at,omitempty"`
	Note           string `json:"note,omitempty"`
}

func cmdQueueList(args []string, stdout, stderr io.Writer, deps queueDeps) error {
	fs := flag.NewFlagSet("queue list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "emit JSON instead of human-readable text")
	showAll := fs.Bool("all", false, "include containers whose updates are not in the latest scan")
	fs.String("data-dir", os.Getenv("BULWARK_DATA_DIR"), "directory holding persistent state")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	st, cleanup, err := openQueueStore(fs, deps)
	if err != nil {
		return err
	}
	defer cleanup()

	rows, err := buildQueueRows(st, *showAll)
	if err != nil {
		return err
	}

	if *jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rows)
	}
	if len(rows) == 0 {
		fmt.Fprintln(stdout, "queue is empty.")
		return nil
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CONTAINER\tLEVEL\tVERSION\tDECISION\tNOTE")
	for _, r := range rows {
		version := r.From + " → " + r.To
		if r.From == "" && r.To == "" {
			version = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			r.Container, nonEmpty(r.Level, "-"), version,
			r.Decision, nonEmpty(r.Note, ""),
		)
	}
	return tw.Flush()
}

// buildQueueRows merges the latest scan's pending REVIEW updates with the
// approval store. Each (container, digest) pair appears once. Rows from the
// latest scan that have no decision are flagged "pending"; recorded
// decisions are surfaced verbatim.
func buildQueueRows(st *store.Store, showAll bool) ([]queueRow, error) {
	scans, err := st.ListScans(1)
	if err != nil {
		return nil, err
	}
	approvals, err := st.ListApprovals()
	if err != nil {
		return nil, err
	}

	// Index existing decisions for fast lookup.
	byKey := make(map[store.ApprovalKey]store.ApprovalRecord, len(approvals))
	for _, a := range approvals {
		byKey[a.ApprovalKey] = a
	}

	var rows []queueRow
	seen := make(map[store.ApprovalKey]bool)

	if len(scans) == 1 {
		full, err := st.GetScan(scans[0].ID)
		if err == nil {
			for _, r := range full.Results {
				if !r.UpdateAvailable {
					continue
				}
				if r.Level != types.RiskReview && r.Level != types.RiskBreaking {
					continue
				}
				key := store.ApprovalKey{ContainerID: r.ContainerName, RegistryDigest: r.RegistryDigest}
				seen[key] = true
				row := queueRow{
					Container:      r.ContainerName,
					Image:          r.Image,
					Level:          r.Level.String(),
					From:           r.From,
					To:             r.To,
					RegistryDigest: r.RegistryDigest,
					Decision:       "pending",
				}
				if dec, ok := byKey[key]; ok {
					row.Decision = dec.Decision.String()
					row.DecidedBy = dec.DecidedBy
					row.Note = dec.Note
					if !dec.DecidedAt.IsZero() {
						row.DecidedAt = dec.DecidedAt.Local().Format(time.RFC3339)
					}
				}
				rows = append(rows, row)
			}
		}
	}

	if showAll {
		for _, a := range approvals {
			if seen[a.ApprovalKey] {
				continue
			}
			row := queueRow{
				Container:      a.ContainerName,
				Image:          a.Image,
				Level:          a.Level.String(),
				From:           a.From,
				To:             a.To,
				RegistryDigest: a.RegistryDigest,
				Decision:       a.Decision.String(),
				DecidedBy:      a.DecidedBy,
				Note:           a.Note,
			}
			if !a.DecidedAt.IsZero() {
				row.DecidedAt = a.DecidedAt.Local().Format(time.RFC3339)
			}
			rows = append(rows, row)
		}
	}

	return rows, nil
}

// cmdQueueDecision implements both `queue approve` and `queue reject`. It
// resolves the container name to its most recent pending update from scan
// history, then writes the decision.
func cmdQueueDecision(args []string, stdout, stderr io.Writer, deps queueDeps, decision store.ApprovalDecision) error {
	verb := decision.String()
	fs := flag.NewFlagSet("queue "+verb, flag.ContinueOnError)
	fs.SetOutput(stderr)
	note := fs.String("note", "", "optional reason recorded with the decision")
	by := fs.String("by", os.Getenv("USER"), "name recorded as the decision-maker")
	fs.String("data-dir", os.Getenv("BULWARK_DATA_DIR"), "directory holding persistent state")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("queue %s: expected exactly one container name", verb)
	}
	container := fs.Arg(0)

	st, cleanup, err := openQueueStore(fs, deps)
	if err != nil {
		return err
	}
	defer cleanup()

	// Look up the container's most recent pending REVIEW/BREAKING update
	// from the latest scan. We prefer an exact name match; failing that,
	// the user gets a clear error so they can fix their input.
	scans, err := st.ListScans(1)
	if err != nil {
		return err
	}
	if len(scans) == 0 {
		return errors.New("queue: no scan history yet — run `bulwark scan` first")
	}
	full, err := st.GetScan(scans[0].ID)
	if err != nil {
		return err
	}
	var match *store.ScanResultRecord
	for i := range full.Results {
		r := full.Results[i]
		if r.ContainerName != container {
			continue
		}
		if !r.UpdateAvailable {
			continue
		}
		match = &full.Results[i]
		break
	}
	if match == nil {
		return fmt.Errorf("queue: no pending update found for container %q in the latest scan", container)
	}

	rec := store.ApprovalRecord{
		ApprovalKey: store.ApprovalKey{
			ContainerID:    match.ContainerName,
			RegistryDigest: match.RegistryDigest,
		},
		ContainerName: match.ContainerName,
		Image:         match.Image,
		Decision:      decision,
		Note:          *note,
		DecidedBy:     *by,
		DecidedAt:     time.Now().UTC(),
		Level:         match.Level,
		From:          match.From,
		To:            match.To,
	}
	if err := st.RecordDecision(rec); err != nil {
		return err
	}

	digestSummary := match.RegistryDigest
	if len(digestSummary) > 19 {
		digestSummary = digestSummary[:19] + "…"
	}
	fmt.Fprintf(stdout, "%s: %s (%s) → %s\n", verb, container, digestSummary, match.To)
	return nil
}

func cmdQueueForget(args []string, stdout, stderr io.Writer, deps queueDeps) error {
	fs := flag.NewFlagSet("queue forget", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.String("data-dir", os.Getenv("BULWARK_DATA_DIR"), "directory holding persistent state")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if fs.NArg() != 1 {
		return errors.New("queue forget: expected exactly one container name")
	}
	container := fs.Arg(0)
	st, cleanup, err := openQueueStore(fs, deps)
	if err != nil {
		return err
	}
	defer cleanup()

	all, err := st.ListApprovals()
	if err != nil {
		return err
	}
	removed := 0
	for _, a := range all {
		if a.ContainerName != container {
			continue
		}
		if err := st.ForgetDecision(a.ApprovalKey); err != nil {
			return err
		}
		removed++
	}
	if removed == 0 {
		return fmt.Errorf("queue forget: no decisions recorded for container %q", container)
	}
	fmt.Fprintf(stdout, "forgot %d decision(s) for %s.\n", removed, container)
	return nil
}

func cmdQueueClear(args []string, stdout, stderr io.Writer, deps queueDeps) error {
	fs := flag.NewFlagSet("queue clear", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.String("data-dir", os.Getenv("BULWARK_DATA_DIR"), "directory holding persistent state")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	st, cleanup, err := openQueueStore(fs, deps)
	if err != nil {
		return err
	}
	defer cleanup()
	before, _ := st.ListApprovals()
	if err := st.ClearApprovals(); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "cleared %d decision(s); next scan re-evaluates every pending update.\n", len(before))
	return nil
}
