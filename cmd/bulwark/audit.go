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
)

// auditDeps lets tests inject a populated store without touching disk.
type auditDeps struct {
	Store *store.Store
}

// cmdAudit prints the most recent audit-log events recorded by the daemon.
// The log is append-only JSONL at <data-dir>/audit.jsonl; this command is
// a thin reader over it (jq + tail -f also work).
func cmdAudit(args []string, stdout, stderr io.Writer) error {
	return cmdAuditWith(args, stdout, stderr, auditDeps{})
}

func cmdAuditWith(args []string, stdout, stderr io.Writer, deps auditDeps) error {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, `Usage: bulwark audit [flags]

Tail the daemon's audit log — every recorded decision, forgotten decision,
notification-state clear, and apply outcome. The log lives at
<data-dir>/audit.jsonl as append-only newline-delimited JSON.

Flags:`)
		fs.PrintDefaults()
	}
	limit := fs.Int("limit", 50, "maximum number of events to display (newest first)")
	jsonOut := fs.Bool("json", false, "emit JSON-Lines instead of human-readable text")
	dataDir := fs.String("data-dir", os.Getenv("BULWARK_DATA_DIR"), "directory holding persistent state")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}

	st := deps.Store
	if st == nil {
		if *dataDir == "" {
			return errors.New("audit: --data-dir is required (or set BULWARK_DATA_DIR)")
		}
		opened, err := store.Open(*dataDir)
		if err != nil {
			return err
		}
		st = opened
		defer func() { _ = st.Close() }()
	}

	events, err := st.ReadAudit(*limit)
	if err != nil {
		return err
	}
	if *jsonOut {
		enc := json.NewEncoder(stdout)
		for _, e := range events {
			if err := enc.Encode(e); err != nil {
				return err
			}
		}
		return nil
	}
	if len(events) == 0 {
		fmt.Fprintln(stdout, "no audit events recorded.")
		return nil
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TIME\tACTION\tACTOR\tCONTAINER\tDETAIL")
	for _, e := range events {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			e.Time.Local().Format(time.RFC3339),
			e.Action,
			nonEmpty(e.Actor, "-"),
			nonEmpty(e.Container, "-"),
			auditDetailString(e),
		)
	}
	return tw.Flush()
}

// auditDetailString picks the most-informative non-empty field for display.
// Detail wins when set; otherwise we synthesise from decision / level.
func auditDetailString(e store.AuditEvent) string {
	if e.Detail != "" {
		return e.Detail
	}
	parts := []string{}
	if e.Decision != store.DecisionUnknown {
		parts = append(parts, "decision="+e.Decision.String())
	}
	if e.Level != 0 {
		parts = append(parts, "level="+e.Level.String())
	}
	if e.Note != "" {
		parts = append(parts, "note="+e.Note)
	}
	if len(parts) == 0 {
		return "-"
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += " " + p
	}
	return out
}
