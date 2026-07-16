package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeSecretFile writes content to a fresh file under a temp dir and returns
// its path. Values are obvious non-secrets so gitleaks stays quiet.
func writeSecretFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write secret file: %v", err)
	}
	return p
}

func TestResolveSecretEnv_ValueFromFile_TrailingNewlineTrimmed(t *testing.T) {
	const name = "BULWARK_SECRETTEST_FROMFILE"
	t.Setenv(name+"_FILE", writeSecretFile(t, "value-from-file\n"))

	v, found, err := resolveSecretEnv(name)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !found {
		t.Fatal("expected found=true when _FILE is set")
	}
	if v != "value-from-file" {
		t.Errorf("value = %q, want %q (trailing newline should be trimmed)", v, "value-from-file")
	}
}

func TestResolveSecretEnv_InlineOnlyWins(t *testing.T) {
	const name = "BULWARK_SECRETTEST_INLINE"
	t.Setenv(name, "inline-value") // no _FILE

	v, found, err := resolveSecretEnv(name)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !found || v != "inline-value" {
		t.Errorf("value = %q found=%v, want %q true", v, found, "inline-value")
	}
}

func TestResolveSecretEnv_BothSetFailsClosed(t *testing.T) {
	const name = "BULWARK_SECRETTEST_BOTH"
	t.Setenv(name, "inline-value")
	t.Setenv(name+"_FILE", writeSecretFile(t, "file-value"))

	v, found, err := resolveSecretEnv(name)
	if err == nil {
		t.Fatal("expected fail-closed error when both NAME and NAME_FILE are set, got nil")
	}
	if found || v != "" {
		t.Errorf("on ambiguity want (\"\", false), got (%q, %v)", v, found)
	}
	// The error must name both variables and never a value.
	if !strings.Contains(err.Error(), name) || !strings.Contains(err.Error(), name+"_FILE") {
		t.Errorf("error should name both %s and %s_FILE: %v", name, name, err)
	}
	if strings.Contains(err.Error(), "inline-value") || strings.Contains(err.Error(), "file-value") {
		t.Errorf("error must not leak a secret value: %v", err)
	}
}

func TestResolveSecretEnv_MissingFileFailsClosed(t *testing.T) {
	const name = "BULWARK_SECRETTEST_MISSING"
	t.Setenv(name+"_FILE", filepath.Join(t.TempDir(), "does-not-exist"))

	v, found, err := resolveSecretEnv(name)
	if err == nil {
		t.Fatal("expected fail-closed error for a missing _FILE, got nil")
	}
	if found || v != "" {
		t.Errorf("on failure want (\"\", false), got (%q, %v)", v, found)
	}
	if !strings.Contains(err.Error(), name) {
		t.Errorf("error should mention %q: %v", name, err)
	}
}

func TestResolveSecretEnv_DirectoryFailsClosed(t *testing.T) {
	const name = "BULWARK_SECRETTEST_DIR"
	t.Setenv(name+"_FILE", t.TempDir()) // a directory is not readable as a file

	if _, _, err := resolveSecretEnv(name); err == nil {
		t.Fatal("expected fail-closed error when _FILE points at a directory, got nil")
	}
}

func TestResolveSecretEnv_EmptyFileFailsClosed(t *testing.T) {
	const name = "BULWARK_SECRETTEST_EMPTY"
	t.Setenv(name+"_FILE", writeSecretFile(t, "\n")) // trims to empty

	_, _, err := resolveSecretEnv(name)
	if err == nil {
		t.Fatal("expected fail-closed error for an empty secret file, got nil")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error should explain the file is empty: %v", err)
	}
}

func TestResolveSecretEnv_AbsentReturnsNotFound(t *testing.T) {
	v, found, err := resolveSecretEnv("BULWARK_SECRETTEST_DEFINITELY_UNSET")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found || v != "" {
		t.Errorf("absent variable want (\"\", false), got (%q, %v)", v, found)
	}
}

func TestResolveSecretEnv_PresentButEmptyNoFileIsExplicitEmpty(t *testing.T) {
	const name = "BULWARK_SECRETTEST_EMPTY_ENV"
	t.Setenv(name, "")

	v, found, err := resolveSecretEnv(name)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !found || v != "" {
		t.Errorf("present-but-empty var want (\"\", true), got (%q, %v)", v, found)
	}
}

func TestSecretEnv_ReadsFileAndFailsClosed(t *testing.T) {
	const name = "BULWARK_SECRETTEST_HELPER"

	t.Setenv(name+"_FILE", writeSecretFile(t, "helper-secret"))
	if v, err := SecretEnv(name); err != nil || v != "helper-secret" {
		t.Fatalf("SecretEnv from file = (%q, %v), want (%q, nil)", v, err, "helper-secret")
	}

	t.Setenv(name+"_FILE", filepath.Join(t.TempDir(), "gone"))
	if _, err := SecretEnv(name); err == nil {
		t.Fatal("SecretEnv should fail closed on an unreadable _FILE")
	}
}

func TestSecretEnv_BothSetFailsClosed(t *testing.T) {
	const name = "BULWARK_SECRETTEST_HELPER_BOTH"
	t.Setenv(name, "inline-value")
	t.Setenv(name+"_FILE", writeSecretFile(t, "file-value"))

	if _, err := SecretEnv(name); err == nil {
		t.Fatal("SecretEnv should fail closed when both NAME and NAME_FILE are set")
	}
}

func TestLoad_FileSecretSubstitution(t *testing.T) {
	t.Setenv("BULWARK_FILETEST_TOKEN_FILE", writeSecretFile(t, "ha-token-from-file\n"))
	dir := t.TempDir()
	path := filepath.Join(dir, "bulwark.yaml")
	contents := `
notifications:
  homeassistant:
    enabled: true
    url: http://hass.example.com:8123
    token: ${BULWARK_FILETEST_TOKEN}
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write tmp config: %v", err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := c.Notifications.HomeAssistant.Token; got != "ha-token-from-file" {
		t.Errorf("token from _FILE not expanded; got %q", got)
	}
}

func TestLoad_FileSecretMissing_FailsClosed(t *testing.T) {
	t.Setenv("BULWARK_FILETEST_TOKEN_FILE", filepath.Join(t.TempDir(), "absent"))
	dir := t.TempDir()
	path := filepath.Join(dir, "bulwark.yaml")
	contents := `
notifications:
  homeassistant:
    token: ${BULWARK_FILETEST_TOKEN}
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write tmp config: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load should fail closed when a referenced _FILE is unreadable")
	}
}

func TestLoad_FileSecretBothSet_FailsClosed(t *testing.T) {
	t.Setenv("BULWARK_FILETEST_TOKEN", "inline-value")
	t.Setenv("BULWARK_FILETEST_TOKEN_FILE", writeSecretFile(t, "file-value"))
	dir := t.TempDir()
	path := filepath.Join(dir, "bulwark.yaml")
	contents := `
notifications:
  homeassistant:
    token: ${BULWARK_FILETEST_TOKEN}
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write tmp config: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load should fail closed when a ${VAR} has both inline and _FILE set")
	}
}
