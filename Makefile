# Bulwark developer targets.
.PHONY: build test vet fmt gate smoke tools lint vuln sec cover gate-full

build:
	go build ./...

test:
	go test -race -count=1 ./...

vet:
	go vet ./...

fmt:
	@out="$$(gofmt -l $$(git ls-files '*.go'))"; \
	if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

# Full local gate mirroring CI's Go checks.
gate: fmt vet build test

# End-to-end smoke suite: builds the real binary and drives capture / pin /
# canary against hermetic fixtures (no network, no Docker). See smoke/run.sh.
smoke:
	bash smoke/run.sh

# ---------------------------------------------------------------------------
# Pipeline-hardening tooling.
#
# Versions are PINNED. The dev box bakes Go 1.22.12 with GOTOOLCHAIN=local,
# so `@latest` (which now requires Go >= 1.23) fails the toolchain gate. Bump
# these deliberately. Install with `make tools`.
GOLANGCI_LINT_VERSION ?= v1.61.0
GOVULNCHECK_VERSION   ?= v1.1.4
GOSEC_VERSION         ?= v2.20.0
COVER_MIN             ?= 74.0
GOBIN                 ?= $(shell go env GOPATH)/bin

tools:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	go install github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION)

# Static analysis (blocking). Config: .golangci.yml.
lint:
	@command -v $(GOBIN)/golangci-lint >/dev/null 2>&1 || { echo "golangci-lint missing — run: make tools"; exit 1; }
	$(GOBIN)/golangci-lint run ./...

# Supply-chain vulnerability scan (ADVISORY on this box). Reports only vulns
# the code actually reaches. Currently red due to Go 1.22.12 stdlib CVEs — a
# toolchain-patch decision for the maintainer, not a repo fix. Re-add to gate-full once
# the Go patch level is bumped.
vuln:
	@command -v $(GOBIN)/govulncheck >/dev/null 2>&1 || { echo "govulncheck missing — run: make tools"; exit 1; }
	$(GOBIN)/govulncheck ./...

# Security static analysis (ADVISORY — not yet a blocking gate). The current
# 21 findings (file/dir perms, subprocess exec, TLS, file-by-variable) sit in
# the security-sensitive capture/store/registry paths and are under review;
# see internal engineering notes "Pipeline hardening — gosec triage". Do not wire into
# gate-full until each finding is fixed or justified with a #nosec rationale.
sec:
	@command -v $(GOBIN)/gosec >/dev/null 2>&1 || { echo "gosec missing — run: make tools"; exit 1; }
	$(GOBIN)/gosec -quiet ./...

# Coverage floor (blocking). Fails when total statement coverage drops below
# COVER_MIN. Current baseline ~75.1%.
cover:
	@go test -covermode=atomic -coverprofile=/tmp/bulwark.cov ./... >/dev/null
	@tot=$$(go tool cover -func=/tmp/bulwark.cov | awk '/^total:/ {gsub(/%/,"",$$NF); print $$NF}'); \
	echo "total coverage: $$tot% (floor $(COVER_MIN)%)"; \
	awk -v t="$$tot" -v m="$(COVER_MIN)" 'BEGIN { exit (t+0 < m+0) ? 1 : 0 }' || { echo "coverage $$tot% is below floor $(COVER_MIN)%"; exit 1; }

# Extended gate: base gate + static analysis + coverage floor.
#
# vuln and sec are ADVISORY (run them, but not blocking) until two decisions land:
#   - vuln: govulncheck flags 35 Go *stdlib* CVEs tied to the pinned Go 1.22.12
#           toolchain being behind on patch releases (bulwark's own deps are
#           clean/non-affecting). Resolving them means bumping the Go patch
#           level, which collides with GOTOOLCHAIN=local — an infra call for the maintainer.
#   - sec : 21 gosec findings in the capture/store/registry security paths
#           need triage (fix or #nosec rationale). See internal engineering notes.
gate-full: gate lint cover
