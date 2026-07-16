package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ranklancer/bulwark/internal/store"
)

// historyDeps lets tests inject an open store without touching the filesystem
// flag-handling path.
type historyDeps struct {
	Store *store.Store
}

// cmdHistory dispatches `bulwark history <subcommand>`. Subcommands:
//
//	list    print a one-line-per-scan summary (newest first)
//	show    print full per-container detail for one scan
//	clear   remove all dedup state (forces re-notification on next scan)
//	prune   delete scan history files past the retention limit
func cmdHistory(args []string, stdout, stderr io.Writer) error {
	return cmdHistoryWith(args, stdout, stderr, historyDeps{})
}

func cmdHistoryWith(args []string, stdout, stderr io.Writer, deps historyDeps) error {
	if len(args) == 0 {
		printHistoryUsage(stderr)
		return errUsage
	}
	switch args[0] {
	case "-h", "--help", "help":
		printHistoryUsage(stdout)
		return nil
	case "list":
		return cmdHistoryList(args[1:], stdout, stderr, deps)
	case "show":
		return cmdHistoryShow(args[1:], stdout, stderr, deps)
	case "clear":
		return cmdHistoryClear(args[1:], stdout, stderr, deps)
	case "prune":
		return cmdHistoryPrune(args[1:], stdout, stderr, deps)
	default:
		fmt.Fprintf(stderr, "unknown history subcommand: %s\n\n", args[0])
		printHistoryUsage(stderr)
		return errUsage
	}
}

func printHistoryUsage(w io.Writer) {
	fmt.Fprintln(w, `Usage: bulwark history <subcommand> [flags]

Inspect and manage Bulwark's persistent state. Requires either --data-dir or
the BULWARK_DATA_DIR environment variable.

Subcommands:
  list     Print one-line summary of recent scans (newest first)
  show     Print full per-container detail for a single scan
  clear    Remove all notification-dedup state (next scan re-notifies)
  prune    Delete scan history files past the retention limit

Run "bulwark history <subcommand> --help" for command-specific options.`)
}

// openStoreFromFlags is the common flag plumbing for every history subcommand.
// Returns the store, a cleanup func, and any error.
func openStoreFromFlags(fs *flag.FlagSet, deps historyDeps) (*store.Store, func(), error) {
	if deps.Store != nil {
		return deps.Store, func() {}, nil
	}
	dataDir := fs.Lookup("data-dir").Value.String()
	if dataDir == "" {
		dataDir = os.Getenv("BULWARK_DATA_DIR")
	}
	if dataDir == "" {
		return nil, nil, errors.New("history: --data-dir is required (or set BULWARK_DATA_DIR)")
	}
	st, err := store.Open(dataDir)
	if err != nil {
		return nil, nil, err
	}
	return st, func() { _ = st.Close() }, nil
}

func cmdHistoryList(args []string, stdout, stderr io.Writer, deps historyDeps) error {
	fs := flag.NewFlagSet("history list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	limit := fs.Int("limit", 20, "maximum number of scans to display")
	jsonOut := fs.Bool("json", false, "emit JSON instead of human-readable text")
	fs.String("data-dir", os.Getenv("BULWARK_DATA_DIR"), "directory holding persistent state")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	st, cleanup, err := openStoreFromFlags(fs, deps)
	if err != nil {
		return err
	}
	defer cleanup()

	scans, err := st.ListScans(*limit)
	if err != nil {
		return err
	}
	if *jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(scans)
	}
	if len(scans) == 0 {
		fmt.Fprintln(stdout, "no scan history yet — run `bulwark scan --data-dir <path>` first.")
		return nil
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "STARTED\tID\tTOTAL\tPENDING\tBREAKING\tREVIEW\tSAFE\tSKIPPED\tERRORED")
	for _, s := range scans {
		fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n",
			s.StartedAt.Local().Format(time.RFC3339),
			s.ID,
			s.Summary.Total, s.Summary.Pending,
			s.Summary.Breaking, s.Summary.Review, s.Summary.Safe,
			s.Summary.Skipped, s.Summary.Errored,
		)
	}
	return tw.Flush()
}

func cmdHistoryShow(args []string, stdout, stderr io.Writer, deps historyDeps) error {
	fs := flag.NewFlagSet("history show", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "emit JSON instead of human-readable text")
	fs.String("data-dir", os.Getenv("BULWARK_DATA_DIR"), "directory holding persistent state")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if fs.NArg() != 1 {
		return errors.New("history show: expected exactly one scan ID (or 'latest')")
	}
	st, cleanup, err := openStoreFromFlags(fs, deps)
	if err != nil {
		return err
	}
	defer cleanup()

	id := fs.Arg(0)
	if id == "latest" {
		scans, err := st.ListScans(1)
		if err != nil {
			return err
		}
		if len(scans) == 0 {
			return errors.New("history show: no scans recorded")
		}
		id = scans[0].ID
	}
	rec, err := st.GetScan(id)
	if err != nil {
		return err
	}
	if *jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rec)
	}

	fmt.Fprintf(stdout, "Scan %s\n", rec.ID)
	fmt.Fprintf(stdout, "  started:  %s\n", rec.StartedAt.Local().Format(time.RFC3339))
	fmt.Fprintf(stdout, "  finished: %s\n", rec.FinishedAt.Local().Format(time.RFC3339))
	if rec.Host != "" {
		fmt.Fprintf(stdout, "  host:     %s\n", rec.Host)
	}
	fmt.Fprintf(stdout, "  summary:  %d total, %d pending (%d breaking / %d review / %d safe), %d skipped, %d errored\n\n",
		rec.Summary.Total, rec.Summary.Pending,
		rec.Summary.Breaking, rec.Summary.Review, rec.Summary.Safe,
		rec.Summary.Skipped, rec.Summary.Errored,
	)
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CONTAINER\tIMAGE\tSTATUS\tDETAIL")
	for _, r := range rec.Results {
		status, detail := historyStatusFor(r)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.ContainerName, r.Image, status, detail)
	}
	return tw.Flush()
}

func historyStatusFor(r store.ScanResultRecord) (string, string) {
	switch {
	case r.Error != "":
		return "ERROR", r.Error
	case r.Skipped:
		return "SKIPPED", r.SkipReason
	case !r.UpdateAvailable:
		return "current", "no digest movement"
	}
	risk := strings.ToUpper(r.Level.String())
	delta := r.From + " → " + r.To
	if r.From == "" && r.To == "" {
		delta = r.Kind.String()
	}
	return risk, delta
}

func cmdHistoryClear(args []string, stdout, stderr io.Writer, deps historyDeps) error {
	fs := flag.NewFlagSet("history clear", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.String("data-dir", os.Getenv("BULWARK_DATA_DIR"), "directory holding persistent state")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	st, cleanup, err := openStoreFromFlags(fs, deps)
	if err != nil {
		return err
	}
	defer cleanup()
	before, _ := st.ListNotifications()
	if err := st.ClearNotifications(); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "cleared %d notification record(s); next scan will re-notify all pending updates.\n", len(before))
	return nil
}

func cmdHistoryPrune(args []string, stdout, stderr io.Writer, deps historyDeps) error {
	fs := flag.NewFlagSet("history prune", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keep := fs.Int("keep", 30, "number of most-recent scans to retain")
	fs.String("data-dir", os.Getenv("BULWARK_DATA_DIR"), "directory holding persistent state")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	st, cleanup, err := openStoreFromFlags(fs, deps)
	if err != nil {
		return err
	}
	defer cleanup()
	pruned, err := st.PruneHistory(*keep)
	if err != nil {
		return err
	}
	if pruned == 0 {
		fmt.Fprintf(stdout, "nothing to prune (history already <= %d records).\n", *keep)
		return nil
	}
	fmt.Fprintf(stdout, "pruned %d scan record(s) (kept the %d most recent).\n", pruned, *keep)
	return nil
}
