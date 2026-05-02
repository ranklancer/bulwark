// Package updater orchestrates a single container update with image-level
// rollback. The flow:
//
//  1. Pull the new image.
//  2. Inspect the running container (full Config + HostConfig + Networks).
//  3. Stop the running container.
//  4. Rename it to "<name>-bulwark-old" so it survives recreate.
//  5. Create a new container with the same config but the new image.
//  6. Start the new container.
//  7. Wait for health check to pass within HealthTimeout (or for a grace
//     period if no HEALTHCHECK is configured).
//  8. On health success: remove the old container.
//  9. On health failure: stop and remove the new container, rename the old
//     back to its original name, start it. The user is no worse off than
//     before the attempt.
//
// Snapshots, hooks, and Compose-aware multi-container coordination are
// out of scope for this package — they layer on top via callers.
package updater

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/bulwark-docker/bulwark/internal/docker"
)

// DockerClient is the subset of *docker.Client the updater drives. The
// interface mirrors the methods we use, so tests can stub them.
type DockerClient interface {
	PullImage(ctx context.Context, ref string) error
	InspectContainer(ctx context.Context, id string) (*docker.ContainerInspect, error)
	StopContainer(ctx context.Context, id string, timeoutSec int) error
	StartContainer(ctx context.Context, id string) error
	RemoveContainer(ctx context.Context, id string, force bool) error
	RenameContainer(ctx context.Context, id, newName string) error
	CreateContainer(ctx context.Context, name string, cfg docker.CreateContainerConfig) (string, error)
}

// Updater applies a single container update with health-verified rollback.
type Updater struct {
	Docker DockerClient
	Logger *slog.Logger

	// HealthTimeout is the upper bound on how long we wait for the new
	// container to become healthy. Zero means use the default (60s).
	HealthTimeout time.Duration

	// HealthInterval is the polling cadence for health checks. Defaults
	// to 2 seconds.
	HealthInterval time.Duration

	// StartupGrace is how long we wait before the first health check, to
	// give the container time to begin its startup probe. Defaults to 5s.
	StartupGrace time.Duration

	// StopTimeoutSec is passed to the Docker engine when stopping
	// containers. Zero means "use the engine default" (typically 10s).
	StopTimeoutSec int

	// Now is overrideable for deterministic tests.
	Now func() time.Time
}

// Result describes the outcome of one update attempt.
type Result struct {
	OldContainerID string
	NewContainerID string
	OldImage       string
	NewImage       string
	HealthStatus   docker.HealthStatus
	RolledBack     bool
	Err            error
}

// Apply runs the full pull + recreate + verify + (rollback) pipeline.
// The targetImage is the new image reference (e.g. "lscr.io/.../sonarr:4.0.11-ls47").
// The returned Result is always non-zero — Err is set when the update was
// not successful (whether or not rollback succeeded).
func (u *Updater) Apply(ctx context.Context, containerID, targetImage string) Result {
	logger := u.Logger
	if logger == nil {
		logger = slog.Default()
	}
	res := Result{NewImage: targetImage}

	// --- 1. Pull -----------------------------------------------------------
	logger.Info("updater: pulling image", "image", targetImage)
	if err := u.Docker.PullImage(ctx, targetImage); err != nil {
		res.Err = fmt.Errorf("pull: %w", err)
		return res
	}

	// --- 2. Inspect --------------------------------------------------------
	insp, err := u.Docker.InspectContainer(ctx, containerID)
	if err != nil {
		res.Err = fmt.Errorf("inspect: %w", err)
		return res
	}
	if insp == nil {
		res.Err = errors.New("inspect: container not found")
		return res
	}
	res.OldContainerID = insp.ID
	res.OldImage = insp.ImageRef
	originalName := insp.NameWithoutSlash()
	if originalName == "" {
		res.Err = errors.New("inspect: container has no name")
		return res
	}

	// --- 3. Stop the old container -----------------------------------------
	logger.Info("updater: stopping old container", "container", originalName, "id", insp.ID)
	if err := u.Docker.StopContainer(ctx, insp.ID, u.StopTimeoutSec); err != nil {
		res.Err = fmt.Errorf("stop old: %w", err)
		return res
	}

	// --- 4. Rename old to preserve it for rollback -------------------------
	preservedName := originalName + "-bulwark-old"
	if err := u.Docker.RenameContainer(ctx, insp.ID, preservedName); err != nil {
		// Try to start the old container back up so we don't leave it stopped.
		_ = u.Docker.StartContainer(ctx, insp.ID)
		res.Err = fmt.Errorf("rename old: %w", err)
		return res
	}

	// --- 5. Create the new container ---------------------------------------
	createCfg, err := docker.NewCreateConfigFromInspect(insp, targetImage)
	if err != nil {
		_ = u.rollbackPreserved(ctx, insp.ID, originalName, preservedName, "", logger)
		res.RolledBack = true
		res.Err = fmt.Errorf("build create config: %w", err)
		return res
	}
	newID, err := u.Docker.CreateContainer(ctx, originalName, createCfg)
	if err != nil {
		_ = u.rollbackPreserved(ctx, insp.ID, originalName, preservedName, "", logger)
		res.RolledBack = true
		res.Err = fmt.Errorf("create new: %w", err)
		return res
	}
	res.NewContainerID = newID

	// --- 6. Start the new container ----------------------------------------
	if err := u.Docker.StartContainer(ctx, newID); err != nil {
		_ = u.rollbackPreserved(ctx, insp.ID, originalName, preservedName, newID, logger)
		res.RolledBack = true
		res.Err = fmt.Errorf("start new: %w", err)
		return res
	}

	// --- 7. Health verification --------------------------------------------
	healthy, finalStatus, healthErr := u.waitForHealthy(ctx, newID)
	res.HealthStatus = finalStatus
	if !healthy {
		_ = u.rollbackPreserved(ctx, insp.ID, originalName, preservedName, newID, logger)
		res.RolledBack = true
		if healthErr != nil {
			res.Err = fmt.Errorf("health: %w", healthErr)
		} else {
			res.Err = fmt.Errorf("health check failed: status=%s", finalStatus)
		}
		return res
	}

	// --- 8. Cleanup: remove the preserved old container --------------------
	if err := u.Docker.RemoveContainer(ctx, insp.ID, true); err != nil {
		// We don't roll back here — the new container is healthy. Leaving
		// the old one around as orphan is recoverable; the user can
		// `docker rm` it manually. Surface as a non-fatal warning.
		logger.Warn("updater: failed to remove preserved old container", "id", insp.ID, "err", err)
	}
	logger.Info("updater: update applied", "container", originalName, "new_id", newID, "old_id", insp.ID)
	return res
}

// rollbackPreserved reverses a partially-completed update. The new
// container (if created) is removed; the preserved old container is
// renamed back to its original name and started.
func (u *Updater) rollbackPreserved(ctx context.Context, oldID, originalName, preservedName, newID string, logger *slog.Logger) error {
	logger.Warn("updater: rolling back", "old_id", oldID, "new_id", newID)

	// Use a fresh context with a generous timeout so an outer cancellation
	// doesn't strand us mid-rollback. Rollback must complete even on
	// shutdown — we'd rather hold up exit by a few seconds than leave a
	// container in an indeterminate state.
	rbCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var rbErrs []string
	if newID != "" {
		if err := u.Docker.StopContainer(rbCtx, newID, u.StopTimeoutSec); err != nil {
			rbErrs = append(rbErrs, "stop new: "+err.Error())
		}
		if err := u.Docker.RemoveContainer(rbCtx, newID, true); err != nil {
			rbErrs = append(rbErrs, "remove new: "+err.Error())
		}
	}
	if err := u.Docker.RenameContainer(rbCtx, oldID, originalName); err != nil {
		rbErrs = append(rbErrs, "rename old back: "+err.Error())
	}
	if err := u.Docker.StartContainer(rbCtx, oldID); err != nil {
		rbErrs = append(rbErrs, "start old: "+err.Error())
	}
	if len(rbErrs) > 0 {
		return fmt.Errorf("rollback errors: %s", strings.Join(rbErrs, "; "))
	}
	return nil
}

// waitForHealthy polls the new container's health status until either it
// reports healthy, an unhealthy status is returned (terminal — no point
// waiting longer), the timeout elapses, or the context is cancelled.
//
// Containers without a HEALTHCHECK have no Health field. For those, we
// require only that the container be Running after the StartupGrace
// period elapses. This is weaker than a real health check but matches
// what most homelab containers actually configure.
func (u *Updater) waitForHealthy(ctx context.Context, id string) (bool, docker.HealthStatus, error) {
	now := u.Now
	if now == nil {
		now = time.Now
	}
	timeout := u.HealthTimeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	interval := u.HealthInterval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	grace := u.StartupGrace
	if grace <= 0 {
		grace = 5 * time.Second
	}

	deadline := now().Add(timeout)
	graceUntil := now().Add(grace)
	var lastStatus docker.HealthStatus

	for {
		select {
		case <-ctx.Done():
			return false, lastStatus, ctx.Err()
		default:
		}

		insp, err := u.Docker.InspectContainer(ctx, id)
		if err != nil {
			return false, lastStatus, err
		}
		if insp == nil {
			return false, lastStatus, errors.New("container disappeared during health wait")
		}
		lastStatus = insp.Health

		switch insp.Health {
		case docker.HealthHealthy:
			return true, insp.Health, nil
		case docker.HealthUnhealthy:
			return false, insp.Health, nil
		case docker.HealthNone:
			// No HEALTHCHECK — accept once Running has held through the grace period.
			if insp.Running && !now().Before(graceUntil) {
				return true, insp.Health, nil
			}
		}

		if now().After(deadline) {
			return false, lastStatus, fmt.Errorf("health check timed out after %s", timeout)
		}

		t := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			t.Stop()
			return false, lastStatus, ctx.Err()
		case <-t.C:
		}
	}
}
