package cve

import "testing"

func TestNewScanSource_TrivyAndGrypeReportDir(t *testing.T) {
	for _, tc := range []struct{ provider, want string }{
		{"", "trivy"}, {"trivy", "trivy"}, {"Trivy", "trivy"}, {"grype", "grype"},
	} {
		s, err := NewScanSource(ScanSourceSpec{Provider: tc.provider, ReportDir: "/reports"})
		if err != nil {
			t.Fatalf("provider %q: %v", tc.provider, err)
		}
		if s.Provider() != tc.want {
			t.Errorf("provider = %q, want %q", s.Provider(), tc.want)
		}
		if s.Kind() != ScanKindReportDir {
			t.Errorf("kind = %q, want report-dir", s.Kind())
		}
	}
}

func TestNewScanSource_Errors(t *testing.T) {
	cases := []struct {
		name string
		spec ScanSourceSpec
	}{
		{"trivy missing report_dir", ScanSourceSpec{Provider: "trivy"}},
		{"server mode unimplemented", ScanSourceSpec{Provider: "trivy", ServerURL: "http://scanner:4954"}},
		{"docker-scout unimplemented", ScanSourceSpec{Provider: "docker-scout"}},
		{"registry unimplemented", ScanSourceSpec{Provider: "registry"}},
		{"unknown provider", ScanSourceSpec{Provider: "nessus", ReportDir: "/x"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := NewScanSource(c.spec); err == nil {
				t.Fatalf("expected an error for %s", c.name)
			}
		})
	}
}

// A ScanSource is a Source (drops into verify.Gate unchanged).
func TestScanSource_IsSource(t *testing.T) {
	var _ Source = NewTrivyReportDir("/reports")
}
