package config

import (
	"fmt"
	"os"
	"strings"
)

// secretFileEnvSuffix is the conventional suffix that points a secret-bearing
// environment variable at a file containing the secret. For a variable NAME,
// NAME_FILE names a file whose contents are used as the value. This mirrors
// the Docker-secrets convention adopted by the official Docker images
// (postgres, mysql, wordpress) and by Grafana, Vaultwarden, GitLab and
// linuxserver.io, so Bulwark drops into a `docker secret` / `secrets:` mount
// workflow without an entrypoint wrapper.
const secretFileEnvSuffix = "_FILE"

// resolveSecretEnv resolves a secret-bearing environment variable, honouring
// the `_FILE` indirection convention. Exactly one source may be provided:
//
//  1. Inline value: a non-empty NAME.
//  2. File indirection: NAME_FILE, a path whose file contents are the secret
//     (a trailing newline is stripped).
//
// If NEITHER is set the variable is absent -> ("", false, nil) and the caller
// applies its default (a `${VAR}` token with no value is left as the literal).
// A bare NAME that is present but empty, with no NAME_FILE, is returned as an
// explicit empty value (found == true) so prior `${VAR}` expansion semantics
// are preserved exactly.
//
// It FAILS CLOSED in three cases, matching the official docker-entrypoint
// behaviour of refusing to guess:
//
//   - BOTH a non-empty NAME and a NAME_FILE are set (ambiguous — the operator
//     must provide exactly one).
//   - NAME_FILE is set but the file is missing or unreadable.
//   - NAME_FILE is set but the file is empty after trimming (a silent empty
//     secret is a misconfiguration, not a valid value).
//
// The secret's value is NEVER included in the error — only the variable names
// and, for I/O failures, the offending path (a path is not the secret) — so
// resolution errors are safe to log.
func resolveSecretEnv(name string) (value string, found bool, err error) {
	v, present := os.LookupEnv(name)
	fileVar := name + secretFileEnvSuffix
	path, fileSet := os.LookupEnv(fileVar)

	hasInline := present && v != ""
	hasFile := fileSet && path != ""

	if hasInline && hasFile {
		return "", false, fmt.Errorf("config: both %s and %s are set; provide exactly one (refusing to guess which to use)", name, fileVar)
	}

	if hasInline {
		return v, true, nil
	}

	if hasFile {
		raw, readErr := os.ReadFile(path) // #nosec G304 -- secret file path from the operator config
		if readErr != nil {
			return "", false, fmt.Errorf("config: read secret for %s from %s: %w", name, fileVar, readErr)
		}
		secret := strings.TrimRight(string(raw), "\r\n")
		if secret == "" {
			return "", false, fmt.Errorf("config: secret file for %s (via %s) at %q is empty", name, fileVar, path)
		}
		return secret, true, nil
	}

	// No file indirection: honour a present-but-empty bare variable so that a
	// deliberately blanked ${VAR} still expands to "" rather than the literal.
	if present {
		return v, true, nil
	}
	return "", false, nil
}

// SecretEnv resolves a secret-bearing environment variable with `_FILE`
// support and returns the resolved value, or "" when neither NAME nor
// NAME_FILE is set. It fails closed when both NAME and NAME_FILE are set, and
// on a set-but-unreadable or empty NAME_FILE. Use it wherever a secret was
// previously read with a bare os.Getenv so the same value can be delivered as
// a mounted Docker secret.
func SecretEnv(name string) (string, error) {
	v, _, err := resolveSecretEnv(name)
	return v, err
}
