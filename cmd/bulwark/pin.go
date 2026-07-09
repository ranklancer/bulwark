package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/bulwark-docker/bulwark/internal/capture"
	"github.com/bulwark-docker/bulwark/internal/store"
)

func cmdPin(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("pin: expected a subcommand: list | rollback")
	}
	switch args[0] {
	case "list":
		return cmdPinList(args[1:], stdout, stderr)
	case "rollback":
		return cmdPinRollback(args[1:], stdout, stderr)
	default:
		return fmt.Errorf("pin: unknown subcommand %q (want list|rollback)", args[0])
	}
}

func cmdPinList(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("pin list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data-dir", os.Getenv("BULWARK_DATA_DIR"), "data dir holding pins.json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dataDir == "" {
		return errors.New("pin list: --data-dir is required")
	}
	pins, err := store.OpenPinStore(*dataDir).List()
	if err != nil {
		return err
	}
	if len(pins) == 0 {
		fmt.Fprintln(stdout, "no pins recorded")
		return nil
	}
	keys := make([]string, 0, len(pins))
	for k := range pins {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p := pins[k]
		fmt.Fprintf(stdout, "%s  %s@%s  [%s]  %s\n", k, p.Ref, p.IndexDigest, p.CanaryState, p.ComposePath)
	}
	return nil
}

func cmdPinRollback(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("pin rollback", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data-dir", os.Getenv("BULWARK_DATA_DIR"), "data dir holding pins.json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return errors.New(`pin rollback: expected exactly one key ("<stack>/<service>")`)
	}
	if *dataDir == "" {
		return errors.New("pin rollback: --data-dir is required")
	}
	ps := store.OpenPinStore(*dataDir)
	rec, ok := ps.Get(rest[0])
	if !ok {
		return fmt.Errorf("pin rollback: no pin recorded for %q", rest[0])
	}
	if rec.BackupPath == "" || rec.ComposePath == "" {
		return fmt.Errorf("pin rollback: %q has no backup/compose path to restore from", rest[0])
	}
	if err := capture.Rollback(rec.BackupPath, rec.ComposePath); err != nil {
		return err
	}
	rec.CanaryState = "rolled-back"
	_ = ps.Set(rest[0], rec)
	fmt.Fprintf(stdout, "rolled back %s: restored %s from %s\n", rest[0], rec.ComposePath, rec.BackupPath)
	return nil
}
