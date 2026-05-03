package scanner

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/bulwark-docker/bulwark/internal/docker"
)

// stackResult builds a minimal Result whose container belongs to a Compose
// project and (optionally) declares depends_on. Sufficient for topology
// tests — the rest of the Result fields aren't consulted by the sort.
func stackResult(project, service, dependsOn string) Result {
	labels := map[string]string{}
	if project != "" {
		labels["com.docker.compose.project"] = project
		labels["com.docker.compose.service"] = service
	}
	if dependsOn != "" {
		labels["com.docker.compose.depends_on"] = dependsOn
	}
	return Result{
		Container: docker.Container{
			Name:   service,
			Labels: labels,
		},
	}
}

// names extracts container names from a slice of Results so tests can
// assert on order without setting up fixtures for every other field.
func names(results []Result) []string {
	out := make([]string, len(results))
	for i, r := range results {
		out[i] = r.Container.Name
	}
	return out
}

func TestSortByDependencies_EmptyAndSingleton(t *testing.T) {
	if got := SortByDependencies(nil, nil); got != nil {
		t.Errorf("nil input: got %v, want nil", got)
	}
	one := []Result{stackResult("demo", "web", "")}
	if got := SortByDependencies(one, nil); !equalNames(got, []string{"web"}) {
		t.Errorf("single input: got %v", names(got))
	}
}

func TestSortByDependencies_NonComposePassthrough(t *testing.T) {
	in := []Result{
		stackResult("", "alpha", ""),
		stackResult("", "bravo", ""),
		stackResult("", "charlie", ""),
	}
	got := SortByDependencies(in, nil)
	if !equalNames(got, []string{"alpha", "bravo", "charlie"}) {
		t.Errorf("non-compose passthrough: got %v", names(got))
	}
}

func TestSortByDependencies_LinearChain(t *testing.T) {
	// web depends_on api; api depends_on db. Apply order: db, api, web.
	in := []Result{
		stackResult("demo", "web", "api:service_started:true"),
		stackResult("demo", "api", "db:service_healthy:true"),
		stackResult("demo", "db", ""),
	}
	got := SortByDependencies(in, nil)
	want := []string{"db", "api", "web"}
	if !equalNames(got, want) {
		t.Errorf("linear chain order: got %v, want %v", names(got), want)
	}
}

func TestSortByDependencies_FanOut_StableTiebreak(t *testing.T) {
	// alpha depends_on shared; bravo depends_on shared.
	// Both alpha and bravo have indegree 1 after shared emits.
	// Stable tiebreak = input order, so alpha emits before bravo.
	in := []Result{
		stackResult("demo", "alpha", "shared:service_started:true"),
		stackResult("demo", "bravo", "shared:service_started:true"),
		stackResult("demo", "shared", ""),
	}
	got := SortByDependencies(in, nil)
	want := []string{"shared", "alpha", "bravo"}
	if !equalNames(got, want) {
		t.Errorf("fan-out order: got %v, want %v", names(got), want)
	}
}

func TestSortByDependencies_NoDependsOn_PreservesInputOrder(t *testing.T) {
	in := []Result{
		stackResult("demo", "second", ""),
		stackResult("demo", "first", ""),
		stackResult("demo", "third", ""),
	}
	got := SortByDependencies(in, nil)
	want := []string{"second", "first", "third"}
	if !equalNames(got, want) {
		t.Errorf("no-deps preserves input order: got %v, want %v", names(got), want)
	}
}

func TestSortByDependencies_InterleavedStacks_FirstOccurrenceWins(t *testing.T) {
	// stack1 entries appear at positions 0 and 2; stack2 entries at 1 and 3.
	// First occurrence of stack1 = position 0 → its sorted block emits first.
	// First occurrence of stack2 = position 1 → its sorted block emits second.
	// Within stack1: api depends_on db → db, api.
	// Within stack2: only one service → cache.
	in := []Result{
		stackResult("stack1", "api", "db:service_started:true"),
		stackResult("stack2", "cache", ""),
		stackResult("stack1", "db", ""),
		stackResult("stack2", "queue", ""),
	}
	got := SortByDependencies(in, nil)
	want := []string{"db", "api", "cache", "queue"}
	if !equalNames(got, want) {
		t.Errorf("interleaved stacks: got %v, want %v", names(got), want)
	}
}

func TestSortByDependencies_NonComposeAndStackInterleaved(t *testing.T) {
	// Standalone container should pass through in input order; the stack's
	// sorted block should emit at its first occurrence.
	in := []Result{
		stackResult("", "standalone-1", ""),
		stackResult("demo", "web", "db:service_started:true"),
		stackResult("", "standalone-2", ""),
		stackResult("demo", "db", ""),
	}
	got := SortByDependencies(in, nil)
	want := []string{"standalone-1", "db", "web", "standalone-2"}
	if !equalNames(got, want) {
		t.Errorf("mixed compose + standalone: got %v, want %v", names(got), want)
	}
}

func TestSortByDependencies_CycleToleratedWithWarning(t *testing.T) {
	// alpha depends_on bravo; bravo depends_on alpha — direct cycle.
	// Both have indegree 1, neither enters queue → both flushed via cycle
	// fallback in input order. Logger should record a warning.
	in := []Result{
		stackResult("demo", "alpha", "bravo:service_started:true"),
		stackResult("demo", "bravo", "alpha:service_started:true"),
	}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	got := SortByDependencies(in, logger)
	want := []string{"alpha", "bravo"}
	if !equalNames(got, want) {
		t.Errorf("cycle fallback order: got %v, want %v", names(got), want)
	}
	if !strings.Contains(buf.String(), "dependency cycle") {
		t.Errorf("cycle should produce a warning log; got %q", buf.String())
	}
}

func TestSortByDependencies_SelfDependencyIgnored(t *testing.T) {
	// alpha depends_on alpha — degenerate; should be treated as no-dep.
	in := []Result{stackResult("demo", "alpha", "alpha:service_started:true")}
	got := SortByDependencies(in, nil)
	if !equalNames(got, []string{"alpha"}) {
		t.Errorf("self-dep got %v", names(got))
	}
}

func TestSortByDependencies_StaleDepIgnored(t *testing.T) {
	// web depends_on absent-service; that dep doesn't exist in the scan.
	// It should be silently ignored — web emits with indegree 0.
	in := []Result{
		stackResult("demo", "web", "absent-service:service_started:true"),
	}
	got := SortByDependencies(in, nil)
	if !equalNames(got, []string{"web"}) {
		t.Errorf("stale dep should not block emit: got %v", names(got))
	}
}

func TestSortByDependencies_DiamondDependency(t *testing.T) {
	// Diamond: top depends_on left + right; left and right both depends_on bottom.
	// Required order: bottom first; left, right next (input-order tiebreak); top last.
	in := []Result{
		stackResult("demo", "top", "left:service_started:true,right:service_started:true"),
		stackResult("demo", "left", "bottom:service_started:true"),
		stackResult("demo", "right", "bottom:service_started:true"),
		stackResult("demo", "bottom", ""),
	}
	got := SortByDependencies(in, nil)
	want := []string{"bottom", "left", "right", "top"}
	if !equalNames(got, want) {
		t.Errorf("diamond: got %v, want %v", names(got), want)
	}
}

func equalNames(got []Result, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i, r := range got {
		if r.Container.Name != want[i] {
			return false
		}
	}
	return true
}
