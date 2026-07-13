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
	updated map[string]string
}

func newFakeKomodo() *fakeKomodo {
	return &fakeKomodo{stacks: map[string]KomodoStack{}, updated: map[string]string{}}
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
func (f *fakeKomodo) UpdateStackFileContents(_ context.Context, id, content string) error {
	f.updated[id] = content
	s := f.stacks[id]
	s.FileContents = content
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

func TestKomodoSource_WritePinAppliesViaAPI(t *testing.T) {
	f := newFakeKomodo()
	f.stacks["s7"] = KomodoStack{ID: "s7", Name: "web", FileContents: "services:\n  app:\n    image: nginx:1.27\n"}
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
	if got := f.updated["s7"]; !strings.Contains(got, "nginx:1.27@"+d) {
		t.Fatalf("update did not contain pinned digest: %q", got)
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
	// Cleartext to non-loopback host is refused unless opted in.
	if _, err := NewKomodoClient(KomodoConfig{BaseURL: "http://k.example:9120", APIKey: "k", APISecret: "s"}); err == nil {
		t.Fatal("cleartext non-loopback base must be refused")
	}
	if _, err := NewKomodoClient(KomodoConfig{BaseURL: "http://127.0.0.1:9120", APIKey: "k", APISecret: "s"}); err != nil {
		t.Fatalf("loopback cleartext should be allowed: %v", err)
	}
}

func TestHTTPKomodoClient_RoundTrip(t *testing.T) {
	var gotKey, gotSecret string
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
				"config": map[string]any{"file_contents": "services:\n  app:\n    image: nginx:1.27\n"},
			})
		case r.URL.Path == "/write" && req.Type == "UpdateStack":
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
	if err != nil || !strings.Contains(st.FileContents, "nginx:1.27") {
		t.Fatalf("GetStack: err=%v st=%+v", err, st)
	}
	if err := c.UpdateStackFileContents(context.Background(), "s1", "x"); err != nil {
		t.Fatal(err)
	}
	if gotKey != "KEY" || gotSecret != "SEC" {
		t.Fatalf("auth headers not set: key=%q secret=%q", gotKey, gotSecret)
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

func TestKomodoStackJSON_GitSignal(t *testing.T) {
	repo := komodoStackJSON{ID: "1", Config: &struct {
		FileContents string `json:"file_contents"`
		Repo         string `json:"repo"`
		LinkedRepo   string `json:"linked_repo"`
		FilesOnHost  bool   `json:"files_on_host"`
	}{Repo: "org/repo"}}
	if !repo.toStack().Git {
		t.Fatal("non-empty repo must flag Git")
	}
	linked := komodoStackJSON{ID: "2", Config: &struct {
		FileContents string `json:"file_contents"`
		Repo         string `json:"repo"`
		LinkedRepo   string `json:"linked_repo"`
		FilesOnHost  bool   `json:"files_on_host"`
	}{LinkedRepo: "abc"}}
	if !linked.toStack().Git {
		t.Fatal("non-empty linked_repo must flag Git")
	}
	ui := komodoStackJSON{ID: "3", Config: &struct {
		FileContents string `json:"file_contents"`
		Repo         string `json:"repo"`
		LinkedRepo   string `json:"linked_repo"`
		FilesOnHost  bool   `json:"files_on_host"`
	}{FileContents: "services: {}"}}
	if ui.toStack().Git {
		t.Fatal("UI-defined stack must not flag Git")
	}
}
func TestKomodoSource_WritePinRefusesOnDrift(t *testing.T) {
	f := newFakeKomodo()
	// The live file no longer contains OldValue -> fail-closed drift guard: refuse
	// the write rather than corrupt content that changed since propose.
	f.stacks["d1"] = KomodoStack{ID: "d1", Name: "drift", FileContents: "services:\n  app:\n    image: nginx:1.28\n"}
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
