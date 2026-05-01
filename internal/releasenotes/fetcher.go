package releasenotes

import (
	"context"
	"fmt"

	"github.com/bulwark-docker/bulwark/internal/registry"
)

// Fetcher resolves release notes for an image reference end-to-end:
// image → source repo → candidate tags → notes.
type Fetcher struct {
	Mapper *Mapper
	GitHub *GitHubClient
}

// NewFetcher returns a Fetcher with default mapper and GitHub client.
func NewFetcher() *Fetcher {
	return &Fetcher{Mapper: NewMapper(), GitHub: NewGitHubClient()}
}

// Result is the full outcome of a fetch attempt: which source was tried, what
// (if anything) we found. Both Source and Notes may be zero-valued.
type Result struct {
	Source Source
	Notes  *Notes
}

// Found reports whether the fetcher located a release.
func (r Result) Found() bool { return r.Notes != nil }

// Fetch attempts to load release notes for ref. Errors are returned only for
// transport-level problems; the absence of release notes is signalled by
// Result.Found() == false (no error).
func (f *Fetcher) Fetch(ctx context.Context, ref registry.Reference) (Result, error) {
	if f == nil || f.Mapper == nil {
		return Result{}, nil
	}
	src, ok := f.Mapper.Map(ref)
	if !ok {
		return Result{}, nil
	}
	candidates := CandidateTags(ref.Tag)
	if len(candidates) == 0 {
		return Result{Source: src}, nil
	}
	switch src.Provider {
	case ProviderGitHub:
		if f.GitHub == nil {
			return Result{Source: src}, nil
		}
		notes, err := f.GitHub.FetchAny(ctx, src.Owner, src.Repo, candidates)
		if err != nil {
			return Result{Source: src}, err
		}
		return Result{Source: src, Notes: notes}, nil
	default:
		return Result{Source: src}, fmt.Errorf("releasenotes: unsupported provider %q", src.Provider)
	}
}
