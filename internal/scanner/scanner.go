// Package scanner enumerates the containers running on the local host and
// asks the classifier whether any of them have a pending update worth
// surfacing. It is the integration point between the Docker socket client,
// the OCI registry client, the release-notes fetcher, and the classifier.
//
// The scanner is read-only — it never pulls, recreates, or otherwise mutates
// containers. Update orchestration arrives in a later phase.
package scanner

import (
	"context"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/bulwark-docker/bulwark/internal/classifier"
	"github.com/bulwark-docker/bulwark/internal/cve"
	"github.com/bulwark-docker/bulwark/internal/config"
	"github.com/bulwark-docker/bulwark/internal/docker"
	"github.com/bulwark-docker/bulwark/internal/registry"
	"github.com/bulwark-docker/bulwark/internal/releasenotes"
	"github.com/bulwark-docker/bulwark/pkg/types"
)

// DockerLister is the subset of the docker package the scanner depends on.
// Production wires in *docker.Client; tests use stubs.
type DockerLister interface {
	ListContainers(ctx context.Context, all bool) ([]docker.Container, error)
	InspectImage(ctx context.Context, idOrRef string) (*docker.ImageInspect, error)
}

// DigestResolver is the subset of the registry package the scanner depends on.
type DigestResolver interface {
	Resolve(ctx context.Context, ref registry.Reference) (string, error)
}

// NotesFetcher is the subset of the releasenotes package the scanner depends on.
// Optional — pass nil to skip the release-notes step.
type NotesFetcher interface {
	Fetch(ctx context.Context, ref registry.Reference) (releasenotes.Result, error)
}

// Scanner orchestrates a single one-shot scan.
type Scanner struct {
	Docker      DockerLister
	Registry    DigestResolver
	Notes       NotesFetcher           // optional
	Classifier  *classifier.Classifier // required
	Config      *config.Config         // optional; controls exclusion lists
	Concurrency int                    // workers performing per-container network calls; defaults to 4

	// CVE, when set, enables the security-urgency axis: after the stability
	// verdict the scanner diffs the current vs candidate image's
	// vulnerabilities and attaches a *types.SecurityAssessment. Optional.
	CVE          cve.Source
	CVEThreshold cve.Severity // minimum closed-CVE severity counted toward urgency
}

// Result is the per-container outcome of a scan.
type Result struct {
	Container      docker.Container
	Reference      registry.Reference
	Skipped        bool   // true means no classification was performed
	SkipReason     string // human-readable reason, populated when Skipped is true
	LocalDigest    string // digest of the image currently running, "" if unknown
	RegistryDigest string // digest the registry currently advertises for the same tag
	Assessment     *types.RiskAssessment
	NotesSource    string // human-readable source attribution, e.g. "github.com/owner/repo"
	Err            error  // non-nil for unexpected errors; expected misses (e.g. unparseable ref) populate SkipReason instead
}

// HasUpdate reports whether the registry advertises a different digest than
// what's running locally. False when either side is unknown — callers should
// treat that as "uncertain" rather than "no update".
func (r Result) HasUpdate() bool {
	return r.LocalDigest != "" && r.RegistryDigest != "" && r.LocalDigest != r.RegistryDigest
}

// Scan iterates the host's containers in parallel and returns per-container
// results. The slice order is stable (sorted by container name) so output is
// deterministic across runs.
//
// When all is true, stopped containers are included as well. Errors from the
// initial container listing are returned directly; per-container errors are
// surfaced via Result.Err so a single broken container doesn't fail the run.
func (s *Scanner) Scan(ctx context.Context, all bool) ([]Result, error) {
	if s == nil {
		return nil, errors.New("scanner: nil receiver")
	}
	if s.Docker == nil || s.Registry == nil || s.Classifier == nil {
		return nil, errors.New("scanner: Docker, Registry, and Classifier are required")
	}

	containers, err := s.Docker.ListContainers(ctx, all)
	if err != nil {
		return nil, fmt.Errorf("scanner: list containers: %w", err)
	}

	results := make([]Result, len(containers))
	conc := s.Concurrency
	if conc <= 0 {
		conc = 4
	}
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup

	for i := range containers {
		i, c := i, containers[i]
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = s.scanOne(ctx, c)
		}()
	}
	wg.Wait()

	sort.SliceStable(results, func(i, j int) bool {
		return results[i].Container.Name < results[j].Container.Name
	})
	return results, nil
}

// scanOne is the per-container pipeline. Pre-network filtering happens first
// so excluded containers don't burn network budget.
func (s *Scanner) scanOne(ctx context.Context, c docker.Container) Result {
	r := Result{Container: c}

	overrides := docker.ParseLabels(c.Labels)
	if !overrides.Enabled {
		r.Skipped = true
		r.SkipReason = "bulwark.enable=false on container"
		return r
	}
	if reason := s.matchExclusion(c); reason != "" {
		r.Skipped = true
		r.SkipReason = reason
		return r
	}

	ref, err := registry.Parse(c.Image)
	if err != nil || ref.Repository == "" {
		r.Skipped = true
		r.SkipReason = fmt.Sprintf("image reference %q could not be parsed", c.Image)
		return r
	}
	if ref.Tag == "" {
		r.Skipped = true
		r.SkipReason = "container is digest-pinned; updates can't be detected without a tag"
		return r
	}
	r.Reference = ref

	// Discover the digest of what's currently running. Two sources, in order:
	//   1. RepoDigests on the local image (the digest the daemon recorded when it
	//      pulled this tag). Most accurate.
	//   2. The container's local ImageID as a fallback. Not the registry digest,
	//      but lets us at least detect a *change* relative to a freshly-resolved
	//      registry digest if RepoDigests is missing.
	if c.ImageID != "" {
		insp, err := s.Docker.InspectImage(ctx, c.ImageID)
		if err == nil && insp != nil {
			r.LocalDigest = insp.DigestFor(ref.FullName())
		}
	}

	regDigest, err := s.Registry.Resolve(ctx, ref)
	if err != nil {
		r.Err = fmt.Errorf("registry resolve: %w", err)
		return r
	}
	r.RegistryDigest = regDigest

	// Build the inputs to the classifier. The current ImageInfo carries the
	// digest the local daemon has; the available ImageInfo carries the digest
	// the registry now advertises. When the local digest is unknown, the
	// classifier still produces a verdict (low confidence) based on the tag.
	current := types.ImageInfo{Repository: ref.FullName(), Tag: ref.Tag, Digest: r.LocalDigest}
	available := types.ImageInfo{Repository: ref.FullName(), Tag: ref.Tag, Digest: r.RegistryDigest}

	var notes *classifier.ReleaseNotes
	if s.Notes != nil && r.HasUpdate() {
		// Skip the network round-trip to GitHub when there's nothing to update;
		// release notes for the *current* digest are uninteresting.
		res, ferr := s.Notes.Fetch(ctx, ref)
		if ferr == nil {
			if res.Found() {
				notes = &classifier.ReleaseNotes{URL: res.Notes.URL, Body: res.Notes.Body, Resolved: true}
				r.NotesSource = res.Source.String()
			} else if res.Source != (releasenotes.Source{}) {
				r.NotesSource = res.Source.String() + " (no release found)"
			}
		}
		// Note fetch failures are intentionally non-fatal — we want the verdict.
	}

	assessment, err := s.Classifier.Classify(ctx, current, available, notes)
	if err != nil {
		r.Err = fmt.Errorf("classify: %w", err)
		return r
	}

	// Stack-level YAML override applies first, then per-container label
	// can still ratchet up (same "never silently downgrade" invariant
	// every other ratchet in this codebase respects).
	if stackOverride := s.stackRiskOverride(c); stackOverride > assessment.Level {
		assessment.Level = stackOverride
		assessment.Rationale = fmt.Sprintf("Risk pinned to %s by stack override. (%s)", stackOverride, assessment.Rationale)
	}
	if overrides.RiskOverride != types.RiskUnknown && overrides.RiskOverride > assessment.Level {
		// Labels can only ratchet risk *up*, never down — same invariant as
		// the keyword scanner.
		assessment.Level = overrides.RiskOverride
		assessment.Rationale = fmt.Sprintf("Risk pinned to %s by container label. (%s)", overrides.RiskOverride, assessment.Rationale)
	}
	// Security-urgency axis (opt-in). With a CVE source wired, diff the
	// current vs candidate image's vulnerabilities and attach the resulting
	// urgency. This is additive: it never mutates assessment.Level. Lookup
	// failures are non-fatal — the stability verdict still stands.
	if s.CVE != nil && r.HasUpdate() {
		curV, cerr := s.CVE.Vulns(ctx, current.Reference())
		candV, nerr := s.CVE.Vulns(ctx, available.Reference())
		if cerr == nil && nerr == nil {
			sa := cve.AssessUpgrade(curV, candV, s.CVEThreshold)
			if sa.ClosedCount > 0 {
				sa.Source = "trivy"
				assessment.Security = &sa
			}
		}
	}
	r.Assessment = assessment
	return r
}

// stackRiskOverride returns the parsed RiskLevel from the stack-level YAML
// override (`overrides.stacks.<compose-project>.risk_override`), or
// RiskUnknown when no project label is set or no override matches.
//
// Stack overrides are the operator-friendly counterpart to per-container
// labels: rather than annotating every service in `media` with
// `bulwark.risk: review`, set it once in `overrides.stacks.media.risk_override`
// and every container in that Compose project inherits it.
func (s *Scanner) stackRiskOverride(c docker.Container) types.RiskLevel {
	if s.Config == nil {
		return types.RiskUnknown
	}
	project := c.ComposeProject()
	if project == "" {
		return types.RiskUnknown
	}
	ov, ok := s.Config.Overrides.Stacks[project]
	if !ok || ov.RiskOverride == "" {
		return types.RiskUnknown
	}
	return types.ParseRiskLevel(ov.RiskOverride)
}

// matchExclusion returns a non-empty reason string when the container is
// excluded by the loaded config, or "" otherwise.
func (s *Scanner) matchExclusion(c docker.Container) string {
	if s.Config == nil {
		return ""
	}
	for _, n := range s.Config.Exclude.Containers {
		if n == c.Name {
			return "container excluded by config"
		}
	}
	if proj := c.ComposeProject(); proj != "" {
		for _, n := range s.Config.Exclude.Stacks {
			if n == proj {
				return "stack excluded by config"
			}
		}
	}
	for _, pat := range s.Config.Exclude.Images {
		if matched, _ := path.Match(pat, c.Image); matched {
			return "image excluded by config"
		}
		// Also try matching against the repository portion (without tag),
		// which is how users most naturally write "postgres:*".
		if i := strings.LastIndex(c.Image, ":"); i >= 0 {
			if matched, _ := path.Match(pat, c.Image[:i]); matched {
				return "image excluded by config"
			}
		}
	}
	return ""
}
