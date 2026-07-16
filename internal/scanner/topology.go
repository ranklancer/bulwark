package scanner

import (
	"log/slog"
	"sort"
)

// SortByDependencies returns results reordered so that, within each Compose
// project, services are emitted dependency-first: a service that
// depends_on another service is emitted only after the service it depends
// on. Non-Compose results (those without a com.docker.compose.project
// label) pass through in their original order.
//
// Output positioning across stacks is deterministic and locality-
// preserving: the first time a stack is encountered in the input, the
// entire sorted block for that stack is emitted in place; later input
// entries belonging to the same stack are skipped (they're already in the
// emitted block). This keeps interleaved scan output stable and lets
// operators predict the apply order from the input order.
//
// Cycles (Compose technically rejects them at parse time, but
// hand-applied labels don't get that check) are tolerated: cycle members
// are appended in input order with a single warning logged. Bulwark
// prefers a degraded but defined order over refusing to apply.
//
// Dependencies referencing a service that's absent from the scan results
// (excluded, stopped, or simply unknown) are silently ignored — they
// don't gate ordering. This matches Compose's own forgiving runtime
// behaviour for stale depends_on entries.
//
// A nil logger is acceptable; cycle warnings are dropped in that case.
func SortByDependencies(results []Result, logger *slog.Logger) []Result {
	if len(results) < 2 {
		return results
	}
	groups := make(map[string][]int, len(results))
	for i, r := range results {
		proj := r.Container.ComposeProject()
		groups[proj] = append(groups[proj], i)
	}

	emitted := make(map[string]bool, len(groups))
	out := make([]Result, 0, len(results))
	for _, r := range results {
		proj := r.Container.ComposeProject()
		if proj == "" {
			out = append(out, r)
			continue
		}
		if emitted[proj] {
			continue
		}
		emitted[proj] = true
		out = append(out, sortStack(results, groups[proj], proj, logger)...)
	}
	return out
}

// sortStack runs a stable Kahn's-algorithm topological sort over the
// subset of results identified by indexes (all members of one Compose
// project). Stable means: when multiple nodes have indegree 0, the
// lowest input-order index emits first.
func sortStack(all []Result, indexes []int, project string, logger *slog.Logger) []Result {
	n := len(indexes)
	if n <= 1 {
		out := make([]Result, n)
		for i, idx := range indexes {
			out[i] = all[idx]
		}
		return out
	}

	// nameToLocal maps service name → local index within `indexes` (0..n-1).
	nameToLocal := make(map[string]int, n)
	for local, idx := range indexes {
		svc := all[idx].Container.ComposeService()
		if svc == "" {
			continue
		}
		nameToLocal[svc] = local
	}

	indegree := make([]int, n)
	dependents := make([][]int, n) // dependents[local] = locals that depend on local
	for local, idx := range indexes {
		seenDep := make(map[int]struct{})
		for _, dep := range all[idx].Container.DependsOn() {
			depLocal, ok := nameToLocal[dep]
			if !ok {
				continue
			}
			if depLocal == local {
				continue // self-dependency: ignore, would be a cycle of one
			}
			if _, dup := seenDep[depLocal]; dup {
				continue
			}
			seenDep[depLocal] = struct{}{}
			dependents[depLocal] = append(dependents[depLocal], local)
			indegree[local]++
		}
	}

	queue := make([]int, 0, n)
	for local := 0; local < n; local++ {
		if indegree[local] == 0 {
			queue = append(queue, local)
		}
	}

	emitted := make([]bool, n)
	out := make([]Result, 0, n)
	for len(queue) > 0 {
		sort.Ints(queue) // stable: input order = local index order
		head := queue[0]
		queue = queue[1:]
		if emitted[head] {
			continue
		}
		emitted[head] = true
		out = append(out, all[indexes[head]])
		for _, dep := range dependents[head] {
			indegree[dep]--
			if indegree[dep] == 0 {
				queue = append(queue, dep)
			}
		}
	}

	if len(out) < n {
		if logger != nil {
			logger.Warn("scanner: dependency cycle in compose project; cycle members appended in input order",
				"project", project,
				"cycle_count", n-len(out))
		}
		for local := 0; local < n; local++ {
			if !emitted[local] {
				out = append(out, all[indexes[local]])
			}
		}
	}
	return out
}
