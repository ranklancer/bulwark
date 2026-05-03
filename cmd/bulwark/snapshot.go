package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"text/tabwriter"
	"time"

	"github.com/bulwark-docker/bulwark/internal/config"
	"github.com/bulwark-docker/bulwark/internal/snapshot"
)

// snapshotDeps lets tests substitute the backend without standing up a
// real ZFS pool / Btrfs subvolume / restic repository. Production loads
// the backend from YAML config via buildSnapshotBackend.
type snapshotDeps struct {
	Backend snapshot.Backend
}

// cmdSnapshot dispatches to the list / restore / prune subcommands. The
// backend selection comes from `snapshots.backend` in the YAML config.
//
// Usage examples:
//
//	bulwark snapshot list <target>
//	bulwark snapshot restore <id>
//	bulwark snapshot prune <id>
func cmdSnapshot(args []string, stdout, stderr io.Writer) error {
	return cmdSnapshotWith(args, stdout, stderr, snapshotDeps{})
}

func cmdSnapshotWith(args []string, stdout, stderr io.Writer, deps snapshotDeps) error {
	if len(args) == 0 {
		printSnapshotUsage(stderr)
		return errUsage
	}
	switch args[0] {
	case "-h", "--help", "help":
		printSnapshotUsage(stdout)
		return nil
	case "list":
		return runSnapshotList(args[1:], stdout, stderr, deps)
	case "restore":
		return runSnapshotRestore(args[1:], stdout, stderr, deps)
	case "prune":
		return runSnapshotPrune(args[1:], stdout, stderr, deps)
	default:
		fmt.Fprintf(stderr, "unknown snapshot subcommand: %s\n\n", args[0])
		printSnapshotUsage(stderr)
		return errUsage
	}
}

func printSnapshotUsage(w io.Writer) {
	fmt.Fprintln(w, `bulwark snapshot — manage filesystem snapshots taken by the daemon

Subcommands:
  list <target>     List Bulwark-created snapshots for a dataset / path
  restore <id>      Revert a snapshot back into place (destructive)
  prune <id>        Delete a snapshot (frees storage)

The backend (zfs, btrfs, restic) is chosen via snapshots.backend in your
bulwark.yaml. Use --config to point at a non-default config path.`)
}

// resolveBackend returns the test-injected backend or constructs one
// from YAML config. A clear error fires when the daemon isn't
// configured for snapshots — operators get a hint, not a silent no-op.
func resolveBackend(deps snapshotDeps, configPath string, logger *slog.Logger) (snapshot.Backend, error) {
	if deps.Backend != nil {
		return deps.Backend, nil
	}
	if configPath == "" {
		return nil, errors.New("snapshot: --config is required to identify the backend")
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		return nil, fmt.Errorf("snapshot: load config: %w", err)
	}
	b := buildSnapshotBackend(loaded, logger)
	if b == nil {
		return nil, errors.New("snapshot: no backend configured (set snapshots.backend in config)")
	}
	return b, nil
}

func runSnapshotList(args []string, stdout, stderr io.Writer, deps snapshotDeps) error {
	fs := flag.NewFlagSet("snapshot list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path to bulwark.yaml")
	jsonOut := fs.Bool("json", false, "emit JSON instead of human-readable text")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "snapshot list: expected exactly one positional argument (the target)")
		return errUsage
	}
	target := fs.Arg(0)

	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	b, err := resolveBackend(deps, *configPath, logger)
	if err != nil {
		return err
	}
	snaps, err := b.List(context.Background(), target)
	if err != nil {
		return err
	}
	if *jsonOut {
		return writeSnapshotJSON(stdout, snaps)
	}
	if len(snaps) == 0 {
		fmt.Fprintln(stdout, "no snapshots recorded for", target)
		return nil
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tCREATED\tLABEL\tTARGET")
	for _, s := range snaps {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
			s.ID,
			s.CreatedAt.UTC().Format(time.RFC3339),
			nonEmpty(s.Label, "-"),
			s.Target,
		)
	}
	return tw.Flush()
}

func runSnapshotRestore(args []string, stdout, stderr io.Writer, deps snapshotDeps) error {
	fs := flag.NewFlagSet("snapshot restore", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path to bulwark.yaml")
	yes := fs.Bool("yes", false, "skip the destructive-action confirmation prompt")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "snapshot restore: expected exactly one positional argument (the snapshot id)")
		return errUsage
	}
	id := fs.Arg(0)

	if !*yes {
		fmt.Fprintf(stderr,
			"snapshot restore %q is destructive — files written since the snapshot will be discarded.\nRe-run with --yes to confirm.\n",
			id)
		return errors.New("snapshot restore: confirmation required")
	}

	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	b, err := resolveBackend(deps, *configPath, logger)
	if err != nil {
		return err
	}
	if err := b.Restore(context.Background(), id); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "snapshot %s restored.\n", id)
	return nil
}

func runSnapshotPrune(args []string, stdout, stderr io.Writer, deps snapshotDeps) error {
	fs := flag.NewFlagSet("snapshot prune", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path to bulwark.yaml")
	yes := fs.Bool("yes", false, "skip the destructive-action confirmation prompt")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "snapshot prune: expected exactly one positional argument (the snapshot id)")
		return errUsage
	}
	id := fs.Arg(0)

	if !*yes {
		fmt.Fprintf(stderr,
			"snapshot prune %q deletes the snapshot permanently.\nRe-run with --yes to confirm.\n",
			id)
		return errors.New("snapshot prune: confirmation required")
	}

	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	b, err := resolveBackend(deps, *configPath, logger)
	if err != nil {
		return err
	}
	if err := b.Destroy(context.Background(), id); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "snapshot %s pruned.\n", id)
	return nil
}

func writeSnapshotJSON(w io.Writer, snaps []snapshot.Snapshot) error {
	type row struct {
		ID        string    `json:"id"`
		Target    string    `json:"target"`
		Label     string    `json:"label,omitempty"`
		CreatedAt time.Time `json:"created_at"`
	}
	rows := make([]row, len(snaps))
	for i, s := range snaps {
		rows[i] = row{ID: s.ID, Target: s.Target, Label: s.Label, CreatedAt: s.CreatedAt.UTC()}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rows)
}
