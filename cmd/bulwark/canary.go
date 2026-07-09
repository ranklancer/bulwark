package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/bulwark-docker/bulwark/internal/capture"
	"github.com/bulwark-docker/bulwark/internal/config"
	"github.com/bulwark-docker/bulwark/internal/store"
	"github.com/bulwark-docker/bulwark/internal/verify"
)

func cmdCanary(args []string, stdout, stderr io.Writer) error {
	return cmdCanaryWith(args, stdout, stderr, nil)
}

// cmdCanaryWith drives a captured pin through the canary lifecycle over pins.json
// (the digest-pin capture design §6): candidate -> canary -> promoted, with rolled-back as the failure
// terminal. A gate can be injected for promote testing.
func cmdCanaryWith(args []string, stdout, stderr io.Writer, gate gateEvaluator) error {
	if len(args) == 0 {
		return errors.New("canary: expected a subcommand: start | status | promote | rollback")
	}
	switch args[0] {
	case "start":
		return canaryStart(args[1:], stdout, stderr)
	case "status":
		return canaryStatus(args[1:], stdout, stderr)
	case "promote":
		return canaryPromote(args[1:], stdout, stderr, gate)
	case "rollback":
		return canaryRollback(args[1:], stdout, stderr)
	default:
		return fmt.Errorf("canary: unknown subcommand %q (want start|status|promote|rollback)", args[0])
	}
}

func canaryFlags(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet("canary "+name, flag.ContinueOnError)
	dataDir := fs.String("data-dir", os.Getenv("BULWARK_DATA_DIR"), "data dir holding pins.json")
	return fs, dataDir
}

func canaryKey(fs *flag.FlagSet) (string, error) {
	rest := fs.Args()
	if len(rest) != 1 {
		return "", errors.New(`expected exactly one target key ("<stack>/<service>")`)
	}
	return rest[0], nil
}

func loadPin(dataDir, key string) (*store.PinStore, store.PinRecord, error) {
	if dataDir == "" {
		return nil, store.PinRecord{}, errors.New("--data-dir is required")
	}
	ps := store.OpenPinStore(dataDir)
	rec, ok := ps.Get(key)
	if !ok {
		return nil, store.PinRecord{}, fmt.Errorf("no pin recorded for %q (capture --apply it first)", key)
	}
	return ps, rec, nil
}

func canaryTransition(from string, allowed ...string) error {
	if from == "" {
		from = store.CanaryCandidate
	}
	for _, a := range allowed {
		if from == a {
			return nil
		}
	}
	return fmt.Errorf("illegal transition from canary state %q", from)
}

func auditCanary(dataDir, action, key string, rec store.PinRecord, detail string) {
	st, err := store.Open(dataDir)
	if err != nil {
		return
	}
	st.Audit(store.AuditEvent{Action: action, Container: key, Image: rec.Ref + "@" + rec.IndexDigest, Detail: detail})
}

func canaryStart(args []string, stdout, stderr io.Writer) error {
	fs, dataDir := canaryFlags("start")
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	key, err := canaryKey(fs)
	if err != nil {
		return err
	}
	ps, rec, err := loadPin(*dataDir, key)
	if err != nil {
		return err
	}
	if err := canaryTransition(rec.CanaryState, store.CanaryCandidate); err != nil {
		return fmt.Errorf("canary start %s: %w", key, err)
	}
	rec.CanaryState = store.CanaryActive
	if err := ps.Set(key, rec); err != nil {
		return err
	}
	auditCanary(*dataDir, store.ActionCanaryStarted, key, rec, "candidate -> canary")
	fmt.Fprintf(stdout, "canary: %s is now in canary (observe health, then promote)\n", key)
	return nil
}

func canaryStatus(args []string, stdout, stderr io.Writer) error {
	fs, dataDir := canaryFlags("status")
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dataDir == "" {
		return errors.New("canary status: --data-dir is required")
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
		state := p.CanaryState
		if state == "" {
			state = store.CanaryCandidate
		}
		fmt.Fprintf(stdout, "%-28s %-11s %s@%s\n", k, state, p.Ref, p.IndexDigest)
	}
	return nil
}

func canaryPromote(args []string, stdout, stderr io.Writer, gate gateEvaluator) error {
	fs, dataDir := canaryFlags("promote")
	configPath := fs.String("config", "", "config file (to build the trust gate that gates promotion)")
	force := fs.Bool("force", false, "promote even if the trust gate returns block (audited)")
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	key, err := canaryKey(fs)
	if err != nil {
		return err
	}
	ps, rec, err := loadPin(*dataDir, key)
	if err != nil {
		return err
	}
	if err := canaryTransition(rec.CanaryState, store.CanaryActive); err != nil {
		return fmt.Errorf("canary promote %s: %w (start it first)", key, err)
	}
	// Gate promotion on the trust verdict (the digest-pin capture design §6.3). Manual promotion (an internal note)
	// is this CLI action; the daemon reconcile loop adds the health-stable-cycle
	// gate before any auto-promote.
	if gate == nil && *configPath != "" {
		cfg, cerr := config.Load(*configPath)
		if cerr != nil {
			return cerr
		}
		g, gerr := buildVerifyGate(cfg)
		if gerr != nil {
			return gerr
		}
		gate = g
	}
	if gate != nil {
		v := gate.Evaluate(context.Background(), verify.Input{PinnedRef: rec.Ref + "@" + rec.IndexDigest})
		fmt.Fprintf(stdout, "canary: %s trust verdict: %s — %s\n", key, v.Decision, v.Summary())
		if v.Blocked() && !*force {
			return fmt.Errorf("canary promote %s: trust gate returned block; not promoting (use --force to override, audited)", key)
		}
	} else {
		fmt.Fprintln(stdout, "canary: no --config; promoting without a trust-gate check")
	}
	rec.CanaryState = store.CanaryPromoted
	if err := ps.Set(key, rec); err != nil {
		return err
	}
	auditCanary(*dataDir, store.ActionCanaryPromoted, key, rec, "canary -> promoted")
	fmt.Fprintf(stdout, "canary: %s promoted\n", key)
	return nil
}

func canaryRollback(args []string, stdout, stderr io.Writer) error {
	fs, dataDir := canaryFlags("rollback")
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	key, err := canaryKey(fs)
	if err != nil {
		return err
	}
	ps, rec, err := loadPin(*dataDir, key)
	if err != nil {
		return err
	}
	if rec.CanaryState == store.CanaryRolledBack {
		return fmt.Errorf("canary rollback %s: already rolled back", key)
	}
	if rec.BackupPath == "" || rec.ComposePath == "" {
		return fmt.Errorf("canary rollback %s: no backup/compose path to restore from", key)
	}
	if err := capture.Rollback(rec.BackupPath, rec.ComposePath); err != nil {
		return err
	}
	rec.CanaryState = store.CanaryRolledBack
	if err := ps.Set(key, rec); err != nil {
		return err
	}
	auditCanary(*dataDir, store.ActionCanaryRolledBack, key, rec, "rolled back; compose restored from backup")
	fmt.Fprintf(stdout, "canary: %s rolled back — restored %s\n", key, rec.ComposePath)
	return nil
}
