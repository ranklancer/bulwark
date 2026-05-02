package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/bulwark-docker/bulwark/internal/config"
	"github.com/bulwark-docker/bulwark/internal/notifier"
	"github.com/bulwark-docker/bulwark/pkg/types"
)

// notifyTestDeps lets tests inject prebuilt notifiers without going through
// FromConfig — useful for verifying the dispatch flow without standing up
// a real config file.
type notifyTestDeps struct {
	Notifiers []notifier.Notifier
}

func cmdNotifyTest(args []string, stdout, stderr io.Writer) error {
	return cmdNotifyTestWith(args, stdout, stderr, notifyTestDeps{})
}

// cmdNotifyTestWith implements `bulwark notify-test`. It loads the user's
// notification configuration, builds the configured channels, sends a
// single synthetic event to each, and reports per-channel success.
func cmdNotifyTestWith(args []string, stdout, stderr io.Writer, deps notifyTestDeps) error {
	fs := flag.NewFlagSet("notify-test", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, `Usage: bulwark notify-test [flags]

Sends a single synthetic event to every notification channel enabled in the
config. Synthetic events bypass the per-channel min_level filter so the test
always reaches each channel regardless of the configured threshold.

Flags:`)
		fs.PrintDefaults()
	}
	configPath := fs.String("config", "", "path to bulwark.yaml (required unless test deps are injected)")
	level := fs.String("level", "review", "risk level to use for the synthetic event: safe | review | breaking")
	verbose := fs.Bool("v", false, "verbose progress logging on stderr")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return errors.New("notify-test: unexpected positional arguments")
	}

	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: levelFor(*verbose)}))

	notifiers := deps.Notifiers
	if notifiers == nil {
		if *configPath == "" {
			return errors.New("notify-test: --config is required")
		}
		c, err := config.Load(*configPath)
		if err != nil {
			return err
		}
		built, err := notifier.FromConfig(c)
		if err != nil {
			// Partial success — log and proceed with whatever was built.
			logger.Warn("some notification channels failed to construct", "err", err)
		}
		notifiers = built
	}
	if len(notifiers) == 0 {
		return errors.New("notify-test: no notification channels configured")
	}

	risk := types.ParseRiskLevel(*level)
	if risk == types.RiskUnknown {
		return fmt.Errorf("notify-test: --level %q must be safe, review, or breaking", *level)
	}

	event := notifier.Event{
		Container:      "bulwark-test",
		Image:          "registry.example.com/bulwark/test:dev",
		ComposeProject: "bulwark",
		Risk:           risk,
		From:           "1.0.0",
		To:             "1.0.1",
		Kind:           types.ChangePatch,
		Confidence:     types.ConfidenceHigh,
		Rationale:      "Synthetic test event from `bulwark notify-test` — safe to ignore.",
		ReleaseURL:     "https://example.com/notes",
		Timestamp:      time.Now().UTC(),
		Synthetic:      true,
	}

	d := notifier.NewDispatcher(notifiers, logger, 30*time.Second)
	results := d.Dispatch(context.Background(), []notifier.Event{event})

	var failures int
	for _, r := range results {
		switch {
		case r.Err != nil:
			fmt.Fprintf(stdout, "%s: FAIL — %s\n", r.Notifier, r.Err.Error())
			failures++
		default:
			fmt.Fprintf(stdout, "%s: ok (sent %d)\n", r.Notifier, r.Sent)
		}
	}
	if failures > 0 {
		return fmt.Errorf("notify-test: %d of %d channel(s) failed", failures, len(results))
	}
	return nil
}
