package capture

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakePortainer is an in-memory PortainerAPI for testing the Source logic.
type fakePortainer struct {
	stacks  map[int]PortainerStack
	files   map[int]string
	updated map[int]string
}

func newFake() *fakePortainer {
	return &fakePortainer{stacks: map[int]PortainerStack{}, files: map[int]string{}, updated: map[int]string{}}
}
func (f *fakePortainer) ListStacks(_ context.Context) ([]PortainerStack, error) {
	var out []PortainerStack
	for _, s := range f.stacks {
		out = append(out, s)
	}
	return out, nil
}
func (f *fakePortainer) Stack(_ context.Context, id int) (PortainerStack, error) {
	return f.stacks[id], nil
}
func (f *fakePortainer) StackFile(_ context.Context, id int) (string, error) {
	return f.files[id], nil
}
func (f *fakePortainer) UpdateStackFile(_ context.Context, st PortainerStack, content string) error {
	f.updated[st.ID] = content
	f.files[st.ID] = content
	return nil
}

func digest64(c string) string { return "sha256:" + strings.Repeat(c, 64) }

func TestPortainerSource_Kind(t *testing.T) {
	if (&PortainerSource{}).Kind() != KindManaged {
		t.Fatal("Portainer must be an API/DB-managed source")
	}
}

func TestPortainerSource_DiscoverFiltersEndpoint(t *testing.T) {
	f := newFake()
	f.stacks[1] = PortainerStack{ID: 1, Name: "web", EndpointID: 3}
	f.stacks[2] = PortainerStack{ID: 2, Name: "db", EndpointID: 9}
	got, err := (&PortainerSource{API: f, EndpointID: 3}).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "web" || got[0].Path != "1" || got[0].Kind != KindManaged {
		t.Fatalf("Discover = %+v, want only stack web (id 1, managed)", got)
	}
}

func TestPortainerSource_WritePinAppliesViaAPI(t *testing.T) {
	f := newFake()
	f.stacks[7] = PortainerStack{ID: 7, Name: "web", EndpointID: 1, Type: 2, Env: []PortainerEnvVar{}}
	f.files[7] = "services:\n  app:\n    image: nginx:1.27\n"
	src := &PortainerSource{API: f}
	tgt := Target{Name: "web", Path: "7", Kind: KindManaged}
	refs, err := src.LocateImageRefs(context.Background(), tgt)
	if err != nil || len(refs) != 1 || refs[0].Raw != "nginx:1.27" {
		t.Fatalf("locate: err=%v refs=%+v", err, refs)
	}
	d := digest64("a")
	prop, err := src.ProposePin(context.Background(), tgt, refs[0], Pin{IndexDigest: d, IsIndex: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.WritePin(context.Background(), prop); err != nil {
		t.Fatal(err)
	}
	if got := f.updated[7]; !strings.Contains(got, "nginx:1.27@"+d) {
		t.Fatalf("stack not updated with pinned digest: %q", got)
	}
}

func TestPortainerSource_WritePinRefusesGitStack(t *testing.T) {
	f := newFake()
	f.stacks[7] = PortainerStack{ID: 7, Name: "gitweb", Git: true}
	f.files[7] = "services:\n  app:\n    image: nginx:1.27\n"
	prop := Proposal{Path: "7", Line: 3, OldValue: "nginx:1.27", NewValue: "nginx:1.27@" + digest64("b")}
	if _, err := (&PortainerSource{API: f}).WritePin(context.Background(), prop); err == nil {
		t.Fatal("WritePin must refuse a git-managed stack (source of truth is git)")
	}
	if _, ok := f.updated[7]; ok {
		t.Fatal("a git-managed stack must not be updated via the API")
	}
}

func TestPortainerSource_WritePinRefusesOnDrift(t *testing.T) {
	f := newFake()
	f.stacks[7] = PortainerStack{ID: 7, Name: "web", Env: []PortainerEnvVar{}}
	f.files[7] = "services:\n  app:\n    image: nginx:1.27\n"
	prop := Proposal{Path: "7", Line: 3, OldValue: "nginx:1.27", NewValue: "nginx:1.27@" + digest64("c")}
	// Someone changed the stack file after the proposal was computed.
	f.files[7] = "services:\n  app:\n    image: caddy:2\n"
	if _, err := (&PortainerSource{API: f}).WritePin(context.Background(), prop); err == nil {
		t.Fatal("WritePin must refuse when the stack file drifted since propose")
	}
}

func TestPortainerSource_WritePinNoOp(t *testing.T) {
	f := newFake()
	f.stacks[7] = PortainerStack{ID: 7}
	res, err := (&PortainerSource{API: f}).WritePin(context.Background(), Proposal{Path: "7", NoOp: true})
	if err != nil || !res.NoOp {
		t.Fatalf("no-op proposal must return NoOp without an API call: res=%+v err=%v", res, err)
	}
	if len(f.updated) != 0 {
		t.Fatal("no-op must not call the API")
	}
}

func TestNewPortainerClient_Validation(t *testing.T) {
	if _, err := NewPortainerClient(PortainerConfig{BaseURL: "", APIKey: "k"}); err == nil {
		t.Error("empty url must be rejected")
	}
	if _, err := NewPortainerClient(PortainerConfig{BaseURL: "ftp://x", APIKey: "k"}); err == nil {
		t.Error("non-http(s) scheme must be rejected")
	}
	if _, err := NewPortainerClient(PortainerConfig{BaseURL: "https://p:9443", APIKey: ""}); err == nil {
		t.Error("empty api key must be rejected")
	}
	if _, err := NewPortainerClient(PortainerConfig{BaseURL: "https://p:9443", APIKey: "k"}); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
}

func TestHTTPPortainerClient_RequestsAndAuth(t *testing.T) {
	var gotKey, gotPut string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/stacks", func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("X-API-Key")
		_ = json.NewEncoder(w).Encode([]portainerStackJSON{{ID: 5, Name: "web", EndpointID: 1, Type: 2}})
	})
	mux.HandleFunc("/api/stacks/5/file", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"StackFileContent": "services:\n  a:\n    image: nginx:1\n"})
	})
	mux.HandleFunc("/api/stacks/5", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			b, _ := json.Marshal(nil)
			_ = b
			gotPut = "put"
			w.WriteHeader(http.StatusOK)
			return
		}
		_ = json.NewEncoder(w).Encode(portainerStackJSON{ID: 5, Name: "web"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := NewPortainerClient(PortainerConfig{BaseURL: srv.URL, APIKey: "secret-key", HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	stacks, err := c.ListStacks(context.Background())
	if err != nil || len(stacks) != 1 || stacks[0].Name != "web" {
		t.Fatalf("ListStacks err=%v stacks=%+v", err, stacks)
	}
	if gotKey != "secret-key" {
		t.Errorf("X-API-Key header = %q, want secret-key", gotKey)
	}
	if _, err := c.StackFile(context.Background(), 5); err != nil {
		t.Fatal(err)
	}
	if err := c.UpdateStackFile(context.Background(), PortainerStack{ID: 5, EndpointID: 1}, "x"); err != nil {
		t.Fatal(err)
	}
	if gotPut != "put" {
		t.Error("UpdateStackFile did not issue a PUT")
	}
}

func TestHTTPPortainerClient_GitDetection(t *testing.T) {
	raw := `{"Id":5,"Name":"g","GitConfig":{"URL":"https://example/repo"}}`
	var j portainerStackJSON
	if err := json.Unmarshal([]byte(raw), &j); err != nil {
		t.Fatal(err)
	}
	if !j.toStack().Git {
		t.Fatal("a stack with GitConfig must be detected as git-managed")
	}
}

func TestHTTPPortainerClient_Non2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer srv.Close()
	c, _ := NewPortainerClient(PortainerConfig{BaseURL: srv.URL, APIKey: "k", HTTPClient: srv.Client()})
	if _, err := c.ListStacks(context.Background()); err == nil {
		t.Fatal("a non-2xx response must be an error")
	}
}

func TestRefuseCrossHostRedirect(t *testing.T) {
	orig := httptest.NewRequest(http.MethodGet, "https://portainer.local/api/stacks", nil)
	same := httptest.NewRequest(http.MethodGet, "https://portainer.local/other", nil)
	if err := refuseCrossHostRedirect(same, []*http.Request{orig}); err != nil {
		t.Errorf("same-host redirect must be allowed: %v", err)
	}
	cross := httptest.NewRequest(http.MethodGet, "https://169.254.169.254/latest", nil)
	if err := refuseCrossHostRedirect(cross, []*http.Request{orig}); err == nil {
		t.Error("cross-host redirect must be refused (SSRF guard)")
	}
	// HIGH: a same-host https->http downgrade must be refused (credential leak).
	downgrade := httptest.NewRequest(http.MethodGet, "http://portainer.local/api/stacks", nil)
	if err := refuseCrossHostRedirect(downgrade, []*http.Request{orig}); err == nil {
		t.Fatal("https->http same-host downgrade must be refused (X-API-Key would leak over cleartext)")
	}
}

func TestNewPortainerClient_CleartextBase(t *testing.T) {
	if _, err := NewPortainerClient(PortainerConfig{BaseURL: "http://portainer.example:9000", APIKey: "k"}); err == nil {
		t.Error("cleartext http to a non-loopback host must be refused by default")
	}
	if _, err := NewPortainerClient(PortainerConfig{BaseURL: "http://portainer.example:9000", APIKey: "k", AllowInsecureHTTP: true}); err != nil {
		t.Errorf("explicit AllowInsecureHTTP must permit cleartext http: %v", err)
	}
	if _, err := NewPortainerClient(PortainerConfig{BaseURL: "http://127.0.0.1:9000", APIKey: "k"}); err != nil {
		t.Errorf("cleartext http to loopback must be allowed: %v", err)
	}
}

func TestBlockDangerousConnectIP(t *testing.T) {
	blocked := []string{"169.254.169.254:80", "169.254.169.254:443", "224.0.0.1:53", "0.0.0.0:80"}
	for _, a := range blocked {
		if err := blockDangerousConnectIP("tcp", a, nil); err == nil {
			t.Errorf("connect to %s must be refused (SSRF guard)", a)
		}
	}
	allowed := []string{"127.0.0.1:9443", "192.0.2.10:9443", "10.0.0.5:9443", "192.0.2.10:443"}
	for _, a := range allowed {
		if err := blockDangerousConnectIP("tcp", a, nil); err != nil {
			t.Errorf("connect to %s must be allowed: %v", a, err)
		}
	}
}

func TestGitConfigHasRepo(t *testing.T) {
	raw := func(x string) *json.RawMessage { m := json.RawMessage(x); return &m }
	if gitConfigHasRepo(nil) {
		t.Error("nil GitConfig is not git-managed")
	}
	if !gitConfigHasRepo(raw(`{"URL":"https://example/repo"}`)) {
		t.Error("GitConfig with a repo URL is git-managed")
	}
	if gitConfigHasRepo(raw(`{}`)) {
		t.Error("empty GitConfig object (no URL) is not git-managed")
	}
	if !gitConfigHasRepo(raw(`not json`)) {
		t.Error("unparseable GitConfig must fail closed (treated as git-managed)")
	}
}

func TestPortainerSource_WritePinRefusesNilEnv(t *testing.T) {
	f := newFake()
	f.stacks[7] = PortainerStack{ID: 7, Name: "web"} // Env is nil (contract mismatch)
	f.files[7] = "services:\n  app:\n    image: nginx:1.27\n"
	prop := Proposal{Path: "7", Line: 3, OldValue: "nginx:1.27", NewValue: "nginx:1.27@" + digest64("d")}
	if _, err := (&PortainerSource{API: f}).WritePin(context.Background(), prop); err == nil {
		t.Fatal("WritePin must refuse when the fetched stack has a nil Env (would risk clearing env)")
	}
	if _, ok := f.updated[7]; ok {
		t.Fatal("no update must be sent when Env is nil")
	}
}
