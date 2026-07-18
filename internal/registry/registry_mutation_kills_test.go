package registry

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- auth.go: Credentials.Empty() -------------------------------------
//
// Empty() ANDs together three "field == """ comparisons. Gremlins found
// two live CONDITIONALS_NEGATION survivors here because every existing
// caller (MapAuth.Lookup, DockerConfigAuth tests) only ever exercises
// Credentials values where the Username comparison is already false, so
// the "&&" short-circuits before the Password / IdentityToken terms are
// evaluated and a flipped "==" -> "!=" on either of them never changes
// the observable result. Test Empty() directly with each field set in
// isolation (Username left empty in every case) to force evaluation of
// all three terms.
func TestCredentials_Empty(t *testing.T) {
	cases := []struct {
		name  string
		creds Credentials
		want  bool
	}{
		{"all empty", Credentials{}, true},
		{"username only", Credentials{Username: "u"}, false},
		// kills auth.go:29:40 (CONDITIONALS_NEGATION: Password == "" -> !=)
		{"password only", Credentials{Password: "p"}, false},
		// kills auth.go:29:65 (CONDITIONALS_NEGATION: IdentityToken == "" -> !=)
		{"identity token only", Credentials{IdentityToken: "t"}, false},
		{"all set", Credentials{Username: "u", Password: "p", IdentityToken: "t"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.creds.Empty(); got != tc.want {
				t.Errorf("Credentials%+v.Empty() = %v, want %v", tc.creds, got, tc.want)
			}
		})
	}
}

// --- reference.go: Parse boundary conditions ---------------------------

// TestParse_LeadingAtSignHasNoRepository kills reference.go:77:38
// (CONDITIONALS_BOUNDARY: strings.Index(rest, "@") >= 0 -> > 0). A
// reference that starts with "@" (index 0) must still be treated as
// carrying a digest, which then leaves the repository empty and must be
// rejected. Under the ">" mutant, i==0 fails to trigger the digest
// split, "@sha256:..." is left in `rest`, and Parse builds a bogus
// (non-erroring) repository instead of failing closed.
func TestParse_LeadingAtSignHasNoRepository(t *testing.T) {
	cases := []string{
		"@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"@",
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			if _, err := Parse(in); err == nil {
				t.Fatalf("Parse(%q) = nil error, want a missing-repository error", in)
			} else if !strings.Contains(err.Error(), "missing repository") {
				t.Errorf("Parse(%q) error = %q, want it to mention the missing repository", in, err.Error())
			}
		})
	}
}

// TestParse_LeadingSlashDocumented documents reference.go:86:38
// (CONDITIONALS_BOUNDARY: strings.Index(rest, "/") >= 0 -> > 0). Unlike
// the "@" case above, this mutant is EQUIVALENT and cannot be killed by
// any behavioural test: when the "/" is the first character (index 0),
// `first := rest[:i]` is always "" regardless of whether the boundary
// admits i==0, and isRegistryHost("") unconditionally returns false --
// so the body of the "if" is a no-op either way and `rest` is left
// untouched under both the real code and the mutant. This test pins
// down the (slightly odd but stable) resulting behaviour so a future
// change to isRegistryHost that broke the equivalence would be caught.
func TestParse_LeadingSlashDocumented(t *testing.T) {
	got, err := Parse("/nginx")
	if err != nil {
		t.Fatalf("Parse(%q): %v", "/nginx", err)
	}
	if got.Registry != DefaultRegistry {
		t.Errorf("Registry = %q, want %q", got.Registry, DefaultRegistry)
	}
	if got.Repository != "/nginx" {
		t.Errorf("Repository = %q, want %q", got.Repository, "/nginx")
	}
	if got.Tag != "latest" {
		t.Errorf("Tag = %q, want latest", got.Tag)
	}
}

// --- auth.go: execHelper (docker-credential-<helper> subprocess) -------
//
// execHelper is only exercised indirectly in the rest of the test suite
// through a stubbed DockerConfigAuth.ResolveHelper, so gremlins reported
// every mutant inside it as NOT COVERED. Drive the real subprocess path
// with a fake docker-credential-testhelper script on PATH to pin down
// its error handling and the "<token>" convention.
func TestExecHelper_ParsesCredentialHelperResponses(t *testing.T) {
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "docker-credential-testhelper")
	script := "#!/bin/sh\n" +
		"read host\n" +
		"case \"$host\" in\n" +
		"  success.example.com)\n" +
		"    printf '{\"Username\":\"alice\",\"Secret\":\"s3cr3t-value\"}'\n" +
		"    ;;\n" +
		"  token.example.com)\n" +
		"    printf '{\"Username\":\"<token>\",\"Secret\":\"tok_abcdef123456\"}'\n" +
		"    ;;\n" +
		"  empty.example.com)\n" +
		"    printf '{\"Username\":\"\",\"Secret\":\"\"}'\n" +
		"    ;;\n" +
		"  badjson.example.com)\n" +
		"    printf 'not-json-at-all'\n" +
		"    ;;\n" +
		"  fail.example.com)\n" +
		"    printf 'boom' 1>&2\n" +
		"    exit 1\n" +
		"    ;;\n" +
		"  *)\n" +
		"    printf '{\"Username\":\"unexpected\",\"Secret\":\"unexpected\"}'\n" +
		"    ;;\n" +
		"esac\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	t.Run("basic username password", func(t *testing.T) {
		got, err := execHelper(context.Background(), "testhelper", "success.example.com")
		if err != nil {
			t.Fatalf("execHelper: %v", err)
		}
		if got.Username != "alice" || got.Password != "s3cr3t-value" {
			t.Errorf("got %+v", got)
		}
		if got.IdentityToken != "" {
			t.Errorf("unexpected identity token: %+v", got)
		}
	})

	t.Run("token convention maps to IdentityToken", func(t *testing.T) {
		// kills auth.go:237:19 (CONDITIONALS_NEGATION: Username == "<token>" -> !=)
		got, err := execHelper(context.Background(), "testhelper", "token.example.com")
		if err != nil {
			t.Fatalf("execHelper: %v", err)
		}
		if got.IdentityToken != "tok_abcdef123456" {
			t.Errorf("IdentityToken = %q, want tok_abcdef123456", got.IdentityToken)
		}
		if got.Username != "" || got.Password != "" {
			t.Errorf("token response should not populate Username/Password: %+v", got)
		}
	})

	t.Run("empty response is an error", func(t *testing.T) {
		// kills auth.go:231:19 and 231:40 (CONDITIONALS_NEGATION on the
		// empty-credentials guard's two "== """ comparisons)
		_, err := execHelper(context.Background(), "testhelper", "empty.example.com")
		if err == nil {
			t.Fatal("expected error for empty helper response")
		}
		if !strings.Contains(err.Error(), "empty credentials") {
			t.Errorf("error = %q, want mention of empty credentials", err.Error())
		}
	})

	t.Run("malformed JSON is a decode error, not silently empty", func(t *testing.T) {
		// kills auth.go:228:44 (CONDITIONALS_NEGATION: json.Unmarshal err != nil -> == nil)
		_, err := execHelper(context.Background(), "testhelper", "badjson.example.com")
		if err == nil {
			t.Fatal("expected decode error for malformed JSON")
		}
		if !strings.Contains(err.Error(), "decode") {
			t.Errorf("error = %q, want a decode error (not an empty-credentials error)", err.Error())
		}
	})

	t.Run("nonzero exit surfaces the exec error, not a decode error", func(t *testing.T) {
		// kills auth.go:221:9 (CONDITIONALS_NEGATION: cmd.Output() err != nil -> == nil)
		_, err := execHelper(context.Background(), "testhelper", "fail.example.com")
		if err == nil {
			t.Fatal("expected error for nonzero helper exit")
		}
		if strings.Contains(err.Error(), "decode") {
			t.Errorf("error = %q, exec failure must not be reported as a decode error", err.Error())
		}
		if !strings.Contains(err.Error(), "helper testhelper:") {
			t.Errorf("error = %q, want the exec-failure wrapper", err.Error())
		}
	})
}

// TestDecodeAuthEntry_ColonAtStartMeansEmptyUsername kills a third
// auth.go survivor found on the confirmation Gremlins run (it timed
// out -- not a clean kill -- on the first, load-sensitive baseline
// run): CONDITIONALS_BOUNDARY at auth.go:204:11, `colon < 0` -> `colon
// <= 0`. bytes.IndexByte returns 0 when the decoded "user:pass" string
// begins with ':' (an empty username, e.g. base64(":secret")), which
// is a valid -- if unusual -- Basic-auth entry and must still decode.
// The "<=" mutant treats colon==0 the same as colon==-1 (not found)
// and incorrectly rejects it.
func TestDecodeAuthEntry_ColonAtStartMeansEmptyUsername(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte(":secretpass"))
	got, ok := decodeAuthEntry(dockerConfigAuthEntry{Auth: encoded})
	if !ok {
		t.Fatalf("decodeAuthEntry(%q) ok = false, want true (colon at index 0 is still a colon)", encoded)
	}
	if got.Username != "" || got.Password != "secretpass" {
		t.Errorf("got %+v, want Username=\"\" Password=\"secretpass\"", got)
	}

	// Sanity check the actual "not found" case still behaves the same.
	noColon := base64.StdEncoding.EncodeToString([]byte("nocolonhere"))
	if _, ok := decodeAuthEntry(dockerConfigAuthEntry{Auth: noColon}); ok {
		t.Errorf("decodeAuthEntry(%q) ok = true, want false (no colon present)", noColon)
	}
}
