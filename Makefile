# Bulwark developer targets.
.PHONY: build test vet fmt gate smoke

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
