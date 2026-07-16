package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

// initConfigTemplate is the YAML body emitted by `bulwark init`. The
// %s slot holds a 64-char hex bearer token generated fresh per call.
//
// The template is intentionally short — operators add notifications,
// snapshots, registry auth etc. by graduating to bulwark.example.yaml
// when they need them. The opening comment block warns against
// committing the file (it carries a literal secret).
const initConfigTemplate = `# Bulwark — generated starter config (mode 0600). Do NOT commit this
# file: it carries a literal bearer token. When you're ready to put
# the config in version control, move the token to an environment
# variable and reference via ${BULWARK_API_TOKEN}.

docker:
  host: unix:///var/run/docker.sock

schedule:
  scan_interval: "6h"

api:
  enabled: true
  listen: ":8080"
  auth:
    type: bearer
    token: "%s"

logging:
  level: info
  format: text
`

// cmdInit implements the `bulwark init` subcommand. It generates a
// fresh bearer token + writes a minimal working config to disk, then
// prints the token to stdout (the only place it appears) along with
// the two commands the operator should run next.
//
// Refuses to overwrite an existing file unless --force is passed —
// rotating the token of a deployed instance is intentional, but
// blowing away an operator's hand-edited config by accident is not.
func cmdInit(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, `Usage: bulwark init [flags]

Generate a starter Bulwark config file with a fresh bearer token. The
emitted file works as-is with `+"`bulwark run --config <file>`"+`; visit the
dashboard and paste the printed token at /login to sign in.

Flags:`)
		fs.PrintDefaults()
	}
	output := fs.String("output", "./bulwark.yaml", "destination path for the generated config")
	force := fs.Bool("force", false, "overwrite the destination if it already exists")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return errors.New("init: unexpected positional arguments")
	}

	if !*force {
		if _, err := os.Stat(*output); err == nil {
			return fmt.Errorf("init: %s already exists; pass --force to overwrite", *output)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("init: stat %s: %w", *output, err)
		}
	}

	token, err := generateBearerToken()
	if err != nil {
		return err
	}
	body := fmt.Sprintf(initConfigTemplate, token)
	if err := os.WriteFile(*output, []byte(body), 0o600); err != nil {
		return fmt.Errorf("init: write %s: %w", *output, err)
	}

	fmt.Fprintf(stdout, "Wrote %s (mode 0600).\n\n", *output)
	fmt.Fprintln(stdout, "Bearer token (save this — it appears only once):")
	fmt.Fprintf(stdout, "  %s\n\n", token)
	fmt.Fprintln(stdout, "Next:")
	fmt.Fprintf(stdout, "  bulwark run --config %s --data-dir ./data\n", *output)
	fmt.Fprintln(stdout, "  open http://localhost:8080/   # paste the token at /login")
	return nil
}

// generateBearerToken returns a 32-byte cryptographically-random
// hex-encoded token (64 chars). Same shape as `openssl rand -hex 32`,
// the convention the example yaml + DEPLOY.md document.
func generateBearerToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("init: generate token: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
