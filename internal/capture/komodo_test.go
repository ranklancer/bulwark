package capture

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeKomodo is an in-memory KomodoAPI for testing the Source logic.
type fakeKomodo struct {
	stacks  map[string]KomodoStack
	updated map[string]map[string]any // full config sent to UpdateStackConfig
}

func newFakeKomodo() *fakeKomodo {
	return &fakeKomodo{stacks: map[string]KomodoStack{}, updated: map[string]map[string]any{}}
}
func (f *fakeKomodo) ListStacks(_ context.Context) ([]KomodoStack, error) {
	var out []KomodoStack
	for _, s := range f.stacks {
		out = append(out, KomodoStack{ID: s.ID, Name: s.Name})
	}
	return out, nil
}
func (f *fakeKomodo) GetStack(_ context.Context, idOrName string) (KomodoStack, error) {
	return f.stacks[idOrName], nil
}
func (f *fakeKomodo) UpdateStackConfig(_ context.Context, id string, config map[string]any) error {
	f.updated[id] = config
	s := f.stacks[id]
	if fc, ok := config["file_contents"].(string); ok {
		s.FileContents = fc
	}
	f.stacks[id] = s
	return nil
}

func kdigest64(c string) string { return "sha256:" + strings.Repeat(c, 64) }

func TestKomodoSource_Kind(t *testing.T) {
	if (&KomodoSource{}).Kind() != KindManaged {
		t.Fatal("Komodo must be an API/DB-managed source")
	}
}

func TestKomodoSource_DiscoverListsStacks(t *testing.T) {
	f := newFakeKomodo()
	f.stacks["a1"] = KomodoStack{ID: "a1", Name: "web"}
	got, err := (&KomodoSource{API: f}).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "web" || got[0].Path != "a1" || got[0].Kind != KindManaged {
		t.Fatalf("Discover = %+v, want stack web (id a1, managed)", got)
	}
}

func TestKomodoSource_WritePinAppliesFullConfigPreservingEnv(t *testing.T) {
	f := newFakeKomodo()
	// RawConfig carries environment alongside file_contents; the read-modify-write
	// must re-send it so a pin never wipes env (merge-vs-replace safe).
	raw := json.RawMessage(`{"file_contents":"services:\n  app:\n    image: nginx:1.27\n","environment":"FOO=bar"}`)
	f.stacks["s7"] = KomodoStack{ID: "s7", Name: "web", FileContents: "services:\n  app:\n    image: nginx:1.27\n", RawConfig: raw}
	src := &KomodoSource{API: f}
	tgt := Target{Name: "web", Path: "s7", Kind: KindManaged}
	refs, err := src.LocateImageRefs(context.Background(), tgt)
	if err != nil || len(refs) != 1 || refs[0].Raw != "nginx:1.27" {
		t.Fatalf("locate: err=%v refs=%+v", err, refs)
	}
	d := kdigest64("a")
	prop, err := src.ProposePin(context.Background(), tgt, refs[0], Pin{IndexDigest: d, IsIndex: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.WritePin(context.Background(), prop); err != nil {
		t.Fatal(err)
	}
	sent := f.updated["s7"]
	if sent == nil {
		t.Fatal("no config was sent")
	}
	if fc, _ := sent["file_contents"].(string); !strings.Contains(fc, "nginx:1.27@"+d) {
		t.Fatalf("file_contents not pinned: %q", fc)
	}
	if env, _ := sent["environment"].(string); env != "FOO=bar" {
		t.Fatalf("environment not preserved in full-config write: %q", env)
	}
}

func TestKomodoSource_WritePinRefusesNonDigest(t *testing.T) {
	f := newFakeKomodo()
	f.stacks["n1"] = KomodoStack{ID: "n1", Name: "nd", FileContents: "services:\n  app:\n    image: nginx:1.27\n", RawConfig: json.RawMessage(`{"file_contents":"x"}`)}
	src := &KomodoSource{API: f}
	// NewValue is a tag, not a digest -> must be refused at the write boundary.
	prop := Proposal{Path: "n1", Line: 3, OldValue: "nginx:1.27", NewValue: "nginx:1.28"}
	_, err := src.WritePin(context.Background(), prop)
	if err == nil || !strings.Contains(err.Error(), "non-digest pin") {
		t.Fatalf("want non-digest refusal, got %v", err)
	}
	if _, ok := f.updated["n1"]; ok {
		t.Fatal("must not write a non-digest pin")
	}
}

func TestKomodoSource_WritePinRefusesGitBacked(t *testing.T) {
	f := newFakeKomodo()
	f.stacks["g1"] = KomodoStack{ID: "g1", Name: "gitstack", Git: true, FileContents: "services:\n  app:\n    image: nginx:1.27\n"}
	src := &KomodoSource{API: f}
	prop := Proposal{Path: "g1", Line: 3, OldValue: "nginx:1.27", NewValue: "nginx:1.27@" + kdigest64("b")}
	_, err := src.WritePin(context.Background(), prop)
	if err == nil || !strings.Contains(err.Error(), "repo/resource-sync-backed") {
		t.Fatalf("want git-backed refusal, got %v", err)
	}
	if _, ok := f.updated["g1"]; ok {
		t.Fatal("must not write a git-backed stack")
	}
}

func TestKomodoSource_WritePinRefusesFilesOnHost(t *testing.T) {
	f := newFakeKomodo()
	f.stacks["h1"] = KomodoStack{ID: "h1", Name: "hoststack", FilesOnHost: true, FileContents: "services:\n  app:\n    image: nginx:1.27\n"}
	src := &KomodoSource{API: f}
	prop := Proposal{Path: "h1", Line: 3, OldValue: "nginx:1.27", NewValue: "nginx:1.27@" + kdigest64("c")}
	_, err := src.WritePin(context.Background(), prop)
	if err == nil || !strings.Contains(err.Error(), "files-on-server") {
		t.Fatalf("want files-on-host refusal, got %v", err)
	}
	if _, ok := f.updated["h1"]; ok {
		t.Fatal("must not write a files-on-host stack")
	}
}

func TestKomodoSource_WritePinRefusesEmptyContents(t *testing.T) {
	f := newFakeKomodo()
	f.stacks["e1"] = KomodoStack{ID: "e1", Name: "empty", FileContents: "   "}
	src := &KomodoSource{API: f}
	prop := Proposal{Path: "e1", Line: 3, OldValue: "nginx:1.27", NewValue: "nginx:1.27@" + kdigest64("d")}
	_, err := src.WritePin(context.Background(), prop)
	if err == nil || !strings.Contains(err.Error(), "empty file_contents") {
		t.Fatalf("want empty-contents refusal, got %v", err)
	}
}

func TestKomodoSource_WritePinRefusesOnDrift(t *testing.T) {
	f := newFakeKomodo()
	// The live file no longer contains OldValue -> fail-closed drift guard: refuse.
	f.stacks["d1"] = KomodoStack{ID: "d1", Name: "drift", FileContents: "services:\n  app:\n    image: nginx:1.28\n", RawConfig: json.RawMessage(`{"file_contents":"x"}`)}
	src := &KomodoSource{API: f}
	prop := Proposal{Path: "d1", Line: 3, OldValue: "nginx:1.27", NewValue: "nginx:1.27@" + kdigest64("e")}
	_, err := src.WritePin(context.Background(), prop)
	if err == nil || !strings.Contains(err.Error(), "no longer contains") {
		t.Fatalf("want drift refusal, got %v", err)
	}
	if _, ok := f.updated["d1"]; ok {
		t.Fatal("must not write when the live value drifted")
	}
}

func TestKomodoSource_WritePinRefusesMissingConfig(t *testing.T) {
	f := newFakeKomodo()
	// Non-empty file_contents but no RawConfig object -> cannot guarantee env
	// preservation on a full-config write, so refuse.
	f.stacks["m1"] = KomodoStack{ID: "m1", Name: "noconf", FileContents: "services:\n  app:\n    image: nginx:1.27\n"}
	src := &KomodoSource{API: f}
	prop := Proposal{Path: "m1", Line: 3, OldValue: "nginx:1.27", NewValue: "nginx:1.27@" + kdigest64("f")}
	_, err := src.WritePin(context.Background(), prop)
	if err == nil || !strings.Contains(err.Error(), "no config object") {
		t.Fatalf("want missing-config refusal, got %v", err)
	}
	if _, ok := f.updated["m1"]; ok {
		t.Fatal("must not write without a full config object")
	}
}

func TestNewKomodoClient_Validation(t *testing.T) {
	if _, err := NewKomodoClient(KomodoConfig{BaseURL: "", APIKey: "k", APISecret: "s"}); err == nil {
		t.Fatal("empty base url must error")
	}
	if _, err := NewKomodoClient(KomodoConfig{BaseURL: "ftp://x", APIKey: "k", APISecret: "s"}); err == nil {
		t.Fatal("non-http scheme must error")
	}
	if _, err := NewKomodoClient(KomodoConfig{BaseURL: "https://k.example", APIKey: "", APISecret: "s"}); err == nil {
		t.Fatal("missing api key must error")
	}
	if _, err := NewKomodoClient(KomodoConfig{BaseURL: "https://k.example", APIKey: "k", APISecret: ""}); err == nil {
		t.Fatal("missing api secret must error")
	}
	if _, err := NewKomodoClient(KomodoConfig{BaseURL: "http://k.example:9120", APIKey: "k", APISecret: "s"}); err == nil {
		t.Fatal("cleartext non-loopback base must be refused")
	}
	if _, err := NewKomodoClient(KomodoConfig{BaseURL: "http://127.0.0.1:9120", APIKey: "k", APISecret: "s"}); err != nil {
		t.Fatalf("loopback cleartext should be allowed: %v", err)
	}
}

func TestHTTPKomodoClient_RoundTrip(t *testing.T) {
	var gotKey, gotSecret string
	var sentConfig map[string]any
	seen := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("X-Api-Key")
		gotSecret = r.Header.Get("X-Api-Secret")
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Type   string          `json:"type"`
			Params json.RawMessage `json:"params"`
		}
		_ = json.Unmarshal(body, &req)
		seen[r.URL.Path+":"+req.Type] = true
		switch {
		case r.URL.Path == "/read" && req.Type == "ListStacks":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": "s1", "name": "web"}})
		case r.URL.Path == "/read" && req.Type == "GetStack":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "s1", "name": "web",
				"config": map[string]any{"file_contents": "services:\n  app:\n    image: nginx:1.27\n", "environment": "A=1"},
			})
		case r.URL.Path == "/write" && req.Type == "UpdateStack":
			var p struct {
				ID     string         `json:"id"`
				Config map[string]any `json:"config"`
			}
			_ = json.Unmarshal(req.Params, &p)
			sentConfig = p.Config
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	c, err := NewKomodoClient(KomodoConfig{BaseURL: srv.URL, APIKey: "KEY", APISecret: "SEC", HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	stacks, err := c.ListStacks(context.Background())
	if err != nil || len(stacks) != 1 || stacks[0].Name != "web" {
		t.Fatalf("ListStacks: err=%v stacks=%+v", err, stacks)
	}
	st, err := c.GetStack(context.Background(), "s1")
	if err != nil || !strings.Contains(st.FileContents, "nginx:1.27") || len(st.RawConfig) == 0 {
		t.Fatalf("GetStack: err=%v st=%+v", err, st)
	}
	if err := c.UpdateStackConfig(context.Background(), "s1", map[string]any{"file_contents": "x", "environment": "A=1"}); err != nil {
		t.Fatal(err)
	}
	if gotKey != "KEY" || gotSecret != "SEC" {
		t.Fatalf("auth headers not set: key=%q secret=%q", gotKey, gotSecret)
	}
	if sentConfig["environment"] != "A=1" {
		t.Fatalf("full config not sent on update: %+v", sentConfig)
	}
	for _, want := range []string{"/read:ListStacks", "/read:GetStack", "/write:UpdateStack"} {
		if !seen[want] {
			t.Fatalf("endpoint %q not exercised", want)
		}
	}
}

func TestHTTPKomodoClient_Non2xxErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	c, err := NewKomodoClient(KomodoConfig{BaseURL: srv.URL, APIKey: "k", APISecret: "s", HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ListStacks(context.Background()); err == nil {
		t.Fatal("non-2xx must be an error")
	}
}

func TestKomodoStackJSON_Signals(t *testing.T) {
	mk := func(cfg string) KomodoStack {
		return komodoStackJSON{ID: "x", Name: "n", Config: json.RawMessage(cfg)}.toStack()
	}
	if !mk(`{"repo":"org/repo"}`).Git {
		t.Fatal("non-empty repo must flag Git")
	}
	if !mk(`{"linked_repo":"abc"}`).Git {
		t.Fatal("non-empty linked_repo must flag Git")
	}
	if mk(`{"file_contents":"services: {}"}`).Git {
		t.Fatal("UI-defined stack must not flag Git")
	}
	// Unparseable config -> fail closed (treated as Git so WritePin refuses).
	if !mk(`{bad json`).Git {
		t.Fatal("unparseable config must fail closed to Git")
	}
	// RawConfig is always retained for the read-modify-write path.
	if len(mk(`{"file_contents":"x"}`).RawConfig) == 0 {
		t.Fatal("RawConfig must be retained")
	}
}
