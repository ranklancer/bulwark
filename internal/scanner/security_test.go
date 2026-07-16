package scanner

import (
	"context"
	"strings"
	"testing"

	"github.com/ranklancer/bulwark/internal/classifier"
	"github.com/ranklancer/bulwark/internal/cve"
	"github.com/ranklancer/bulwark/internal/docker"
	"github.com/ranklancer/bulwark/pkg/types"
)

// fakeCVE resolves vulns by the digest embedded in the requested ref.
type fakeCVE struct{ byDigest map[string][]cve.Vuln }

func (f fakeCVE) Vulns(_ context.Context, ref string) ([]cve.Vuln, error) {
	d := ref
	if i := strings.Index(ref, "@"); i >= 0 {
		d = ref[i+1:]
	}
	return f.byDigest[d], nil
}

func TestScan_AttachesSecurityAssessment(t *testing.T) {
	fd := &fakeDocker{
		containers: []docker.Container{{
			ID: "c1", Name: "app", Image: "ghcr.io/owner/app:1.2.3", ImageID: "sha256:local",
			Labels: map[string]string{},
		}},
		images: map[string]*docker.ImageInspect{
			"sha256:local": {RepoDigests: []string{"ghcr.io/owner/app@sha256:cur"}},
		},
	}
	fr := &fakeRegistry{digests: map[string]string{
		"ghcr.io/owner/app:1.2.3": "sha256:cand",
	}}
	fcve := fakeCVE{byDigest: map[string][]cve.Vuln{
		"sha256:cur":  {{ID: "CVE-A", Severity: cve.SeverityCritical}, {ID: "CVE-B", Severity: cve.SeverityHigh}},
		"sha256:cand": {{ID: "CVE-B", Severity: cve.SeverityHigh}},
	}}

	s := &Scanner{
		Docker:       fd,
		Registry:     fr,
		Classifier:   classifier.New(classifier.DefaultConfig()),
		CVE:          fcve,
		CVEThreshold: cve.SeverityCritical,
	}
	results, err := s.Scan(context.Background(), false)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	sec := results[0].Assessment.Security
	if sec == nil {
		t.Fatal("expected a SecurityAssessment to be attached")
	}
	if sec.Urgency != types.UrgencyUrgent {
		t.Errorf("Urgency = %v, want urgent", sec.Urgency)
	}
	if sec.CriticalClosed != 1 || sec.ClosedCount != 1 {
		t.Errorf("closed = %+v, want 1 critical", sec)
	}
}

func TestScan_NoCVESource_NoSecurityAssessment(t *testing.T) {
	fd := &fakeDocker{
		containers: []docker.Container{{
			ID: "c1", Name: "app", Image: "ghcr.io/owner/app:1.2.3", ImageID: "sha256:local",
			Labels: map[string]string{},
		}},
		images: map[string]*docker.ImageInspect{
			"sha256:local": {RepoDigests: []string{"ghcr.io/owner/app@sha256:cur"}},
		},
	}
	fr := &fakeRegistry{digests: map[string]string{"ghcr.io/owner/app:1.2.3": "sha256:cand"}}
	s := &Scanner{Docker: fd, Registry: fr, Classifier: classifier.New(classifier.DefaultConfig())}
	results, _ := s.Scan(context.Background(), false)
	if results[0].Assessment.Security != nil {
		t.Error("no CVE source wired, yet Security was populated")
	}
}
