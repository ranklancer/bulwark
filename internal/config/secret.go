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
// the `_FILE` indirection convention. Precedence, highest first:
//
//  1. Explicit value: a non-empty NAME wins outright.
//  2. File indirection: otherwise, if NAME_FILE is set, the secret is read
//     from that file path (a trailing newline is stripped).
//  3. Absent: neither set -> ("", false, nil); the caller applies its default.
//
// A bare NAME that is present but empty, with no NAME_FILE, is returned as an
// explicit empty value (found == true) so prior `${VAR}` expansion semantics
// are preserved exactly.
//
// It FAILS CLOSED: when NAME_FILE is set but the file is missing, unreadable,
// or empty after trimming, a non-nil error is returned instead of a silent
// empty secret. The secret's value is NEVER included in the error — only the
// variable name and, for I/O failures, the offending path (a path is not the
// secret) — so resolution errors are safe to log.
func resolveSecretEnv(name string) (value string, found bool, err error) {
	v, present := os.LookupEnv(name)
	if present && v != "" {
		return v, true, nil
	}

	fileVar := name + secretFileEnvSuffix
	if path, ok := os.LookupEnv(fileVar); ok && path != "" {
		raw, readErr := os.ReadFile(path)
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
// NAME_FILE is set. It fails closed on a set-but-unreadable or empty
// NAME_FILE. Use it wherever a secret was previously read with a bare
// os.Getenv so the same value can be delivered as a mounted Docker secret.
func SecretEnv(name string) (string, error) {
	v, _, err := resolveSecretEnv(name)
	return v, err
}
