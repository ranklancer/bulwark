package cve

import "testing"

// FuzzParseTrivyReport fuzzes the Trivy JSON report parser (untrusted scanner
// output). Contract: never panic; return either an error or a valid result.
func FuzzParseTrivyReport(f *testing.F) {
	f.Add([]byte(`{"ArtifactName":"nginx:1.27","Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-2024-1","PkgName":"libc","Severity":"HIGH","Title":"x"}]}]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"Results":null}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = ParseTrivyReport(data)
	})
}

// FuzzParseGrypeReport fuzzes the Grype JSON report parser.
func FuzzParseGrypeReport(f *testing.F) {
	f.Add([]byte(`{"matches":[{"vulnerability":{"id":"CVE-2024-2","severity":"Critical"}}],"source":{"target":{"userInput":"redis:7"}}}`))
	f.Add([]byte(`{"matches":[]}`))
	f.Add([]byte(`{`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = ParseGrypeReport(data)
	})
}
