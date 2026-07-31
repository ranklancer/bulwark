//go:build integration

// Package integration contains bulwark's acceptance/integration test lane. It is
// deliberately excluded from `go test ./...`, `make gate`, and
// `make gate-full` by the `integration` build tag above — run it only via
// `make integration` (see the Makefile target staged alongside this file).
//
// TEMPLATE NOTICE: TestMain below boots a generic, representative container
// (redis:7-alpine) purely to prove the testcontainers-go harness works end
// to end — build tag wiring, container lifecycle, port mapping, CI Docker
// availability. It is NOT wired to any bulwark package and asserts nothing
// about bulwark's own behavior. Specialize it before relying on it for real
// coverage: swap the image/wait-strategy for whatever dependency a real
// bulwark integration test needs (e.g. a stub OCI registry container to
// exercise internal/registry, or run the built `bulwark` binary itself
// as a container-under-test), and add real assertions in additional
// `*_test.go` files in this package, guarded by the same `integration`
// build tag.
package integration

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// containerHostPort is set by TestMain and read by tests in this package.
var containerHostPort string

func TestMain(m *testing.M) {
	os.Exit(runMain(m))
}

func runMain(m *testing.M) int {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	req := testcontainers.ContainerRequest{
		// TEMPLATE: generic representative image — replace with the real
		// dependency under test when specializing this lane (see notice above).
		Image:        "redis:7-alpine",
		ExposedPorts: []string{"6379/tcp"},
		WaitingFor:   wait.ForListeningPort("6379/tcp").WithStartupTimeout(60 * time.Second),
	}

	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		log.Printf("integration: failed to start template container: %v", err)
		return 1
	}
	defer func() {
		if tErr := c.Terminate(context.Background()); tErr != nil {
			log.Printf("integration: container terminate error (non-fatal): %v", tErr)
		}
	}()

	host, err := c.Host(ctx)
	if err != nil {
		log.Printf("integration: failed to resolve container host: %v", err)
		return 1
	}
	port, err := c.MappedPort(ctx, "6379/tcp")
	if err != nil {
		log.Printf("integration: failed to resolve mapped port: %v", err)
		return 1
	}
	containerHostPort = fmt.Sprintf("%s:%s", host, port.Port())

	return m.Run()
}

// TestSmoke_ContainerReachable is the one smoke-level assertion this
// template ships with: the harness can dial the container TestMain booted.
// It proves the lane works end to end without asserting anything about
// bulwark itself. Specialize or delete once a real integration test lands.
func TestSmoke_ContainerReachable(t *testing.T) {
	t.Parallel()

	conn, err := net.DialTimeout("tcp", containerHostPort, 5*time.Second)
	if err != nil {
		t.Fatalf("could not dial template container at %s: %v", containerHostPort, err)
	}
	_ = conn.Close()
}
