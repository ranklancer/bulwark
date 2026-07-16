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

	"github.com/ranklancer/bulwark/internal/docker"
	"github.com/ranklancer/bulwark/internal/hooks"
	"github.com/ranklancer/bulwark/internal/snapshot"
	"github.com/ranklancer/bulwark/internal/snapshot/detect"
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

	// Snapshots, when set, takes a filesystem snapshot of SnapshotTarget
	// before the recreate dance. On health failure the snapshot is
	// restored before the container-level rollback finishes; on success
	// the snapshot is destroyed. Setting Snapshots without setting
	// SnapshotTarget on an Apply call is a no-op for that call.
	Snapshots snapshot.Backend

	// MountTable, when non-nil, drives auto-inference of SnapshotTarget
	// when ApplyOptions.SnapshotAutoInfer is true and SnapshotTarget is
	// empty. The updater walks the container's HostConfig.Binds and
	// asks the table for the deepest snapshot-capable mount containing
	// each bind source; the first match becomes the snapshot target.
	// nil disables auto-inference even when the per-container label is
	// set (the operator gets a log warning).
	MountTable *detect.MountTable

	// Hooks runs lifecycle hook scripts. nil means use the default
	// hooks.ExecRunner. Tests inject hooks.FakeRunner.
	Hooks hooks.Runner

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

	// SnapshotID is the ID of the pre-update filesystem snapshot, when
	// one was taken. On success it has been destroyed; on rollback it has
	// been restored. Always empty when no Snapshots backend was active or
	// no SnapshotTarget was supplied.
	SnapshotID string

	Err error
}

// ApplyOptions controls the Apply flow per call. Most fields are optional —
// a zero ApplyOptions still produces a reasonable update.
type ApplyOptions struct {
	// SnapshotTarget tells the configured snapshot backend what to snap.
	// Zero string means "no snapshot for this update". Backends interpret
	// this string in their own terms (ZFS dataset, Btrfs subvolume path,
	// etc.).
	SnapshotTarget string

	// SnapshotLabel is a free-form label embedded in the snapshot name,
	// useful when listing snapshots later. Defaults to the container name.
	SnapshotLabel string

	// PreUpdateHook, PostUpdateHook, RollbackHook are paths to executable
	// scripts on the host. Empty paths disable the corresponding hook.
	// Pre-update failure aborts the update; post-update and rollback
	// failures are logged but non-fatal.
	PreUpdateHook  string
	PostUpdateHook string
	RollbackHook   string

	// SnapshotAutoInfer asks the updater to fill SnapshotTarget by
	// walking the container's HostConfig.Binds against u.MountTable
	// when SnapshotTarget is empty at call time. Set true by callers
	// observing the "bulwark.snapshot.auto" label; explicit
	// SnapshotTarget always wins.
	SnapshotAutoInfer bool
}

// Apply runs the full pull + recreate + verify + (rollback) pipeline.
// The targetImage is the new image reference. ApplyOptions can be passed
// via ApplyWithOptions; this method delegates with zero options.
func (u *Updater) Apply(ctx context.Context, containerID, targetImage string) Result {
	return u.ApplyWithOptions(ctx, containerID, targetImage, ApplyOptions{})
}

// ApplyWithOptions runs the full update pipeline with the specified options.
// The returned Result is always non-zero — Err is set when the update was
// not successful (whether or not rollback succeeded).
func (u *Updater) ApplyWithOptions(ctx context.Context, containerID, targetImage string, opts ApplyOptions) Result {
	logger := u.Logger
	if logger == nil {
		logger = slog.Default()
	}
	hookRunner := u.Hooks
	if hookRunner == nil {
		hookRunner = hooks.ExecRunner{}
	}
	res := Result{NewImage: targetImage}

	// --- 2. Inspect first (we need OldImage for the pre-update hook) ------
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

	// hctx carries the per-update facts every hook receives.
	hctx := hooks.Context{
		Container:   originalName,
		ContainerID: insp.ID,
		OldImage:    insp.ImageRef,
		NewImage:    targetImage,
	}

	// --- 1.5. Pre-update hook ----------------------------------------------
	// Runs BEFORE pull so users can drain connections / take application-
	// level snapshots before any system mutations happen. Failure aborts.
	if opts.PreUpdateHook != "" {
		hctx.Action = hooks.ActionPreUpdate
		out, err := hookRunner.Run(ctx, opts.PreUpdateHook, hctx, 0)
		if err != nil {
			res.Err = fmt.Errorf("pre-update hook: %w", err)
			logger.Warn("updater: pre-update hook failed; aborting update",
				"hook", opts.PreUpdateHook, "container", originalName,
				"output", trimHookOutput(out))
			return res
		}
		logger.Info("updater: pre-update hook ok", "hook", opts.PreUpdateHook, "container", originalName)
	}

	// --- 1. Pull -----------------------------------------------------------
	logger.Info("updater: pulling image", "image", targetImage)
	if err := u.Docker.PullImage(ctx, targetImage); err != nil {
		res.Err = fmt.Errorf("pull: %w", err)
		return res
	}

	// --- 2.4. Auto-infer SnapshotTarget when the operator opted in via
	// the bulwark.snapshot.auto label and didn't supply an explicit
	// dataset. Walks the container's HostConfig.Binds against the
	// daemon's mount table; the first bind whose source lives on a
	// snapshot-capable filesystem (zfs / btrfs) wins. No-op when the
	// mount table is nil or the container has no bind mounts.
	if opts.SnapshotAutoInfer && opts.SnapshotTarget == "" {
		if u.MountTable == nil {
			logger.Warn("updater: snapshot auto-infer requested but no MountTable wired", "container", originalName)
		} else {
			binds, err := detect.ParseHostConfigBinds(insp.HostConfig)
			if err != nil {
				logger.Warn("updater: snapshot auto-infer: parse binds", "container", originalName, "err", err)
			} else if target, ok := detect.InferTargetFromBinds(binds, u.MountTable); ok {
				opts.SnapshotTarget = target
				logger.Info("updater: snapshot auto-infer matched",
					"container", originalName, "target", target)
			} else {
				logger.Info("updater: snapshot auto-infer: no matching bind on a known fs", "container", originalName)
			}
		}
	}

	// --- 2.5. Take a filesystem snapshot, if configured ---------------------
	// We do this AFTER inspect (so we know we'll proceed) but BEFORE
	// stopping the container, so the snapshot captures a quiescent-as-
	// possible state of the volume. (We can't quiesce running data without
	// stopping the container; this is a best-effort point-in-time copy.)
	if u.Snapshots != nil && opts.SnapshotTarget != "" {
		label := opts.SnapshotLabel
		if label == "" {
			label = originalName
		}
		snapID, err := u.Snapshots.Snapshot(ctx, opts.SnapshotTarget, label)
		if err != nil {
			// Snapshot failure aborts BEFORE we've made any container-level
			// changes, so there's nothing to roll back. Surface clearly.
			res.Err = fmt.Errorf("snapshot: %w", err)
			return res
		}
		res.SnapshotID = snapID
		hctx.SnapshotID = snapID
		logger.Info("updater: filesystem snapshot taken", "id", snapID, "target", opts.SnapshotTarget)
	}

	// --- 3. Stop the old container -----------------------------------------
	logger.Info("updater: stopping old container", "container", originalName, "id", insp.ID)
	if err := u.Docker.StopContainer(ctx, insp.ID, u.StopTimeoutSec); err != nil {
		res.Err = fmt.Errorf("stop old: %w", err)
		// We've taken a snapshot but haven't recreated; clean it up so we
		// don't leak resources on retried updates.
		u.tryDestroySnapshot(ctx, &res, logger)
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
		_ = u.rollbackPreserved(ctx, insp.ID, originalName, preservedName, "", res.SnapshotID, hctx, opts.RollbackHook, hookRunner, logger)
		res.RolledBack = true
		res.Err = fmt.Errorf("build create config: %w", err)
		return res
	}
	newID, err := u.Docker.CreateContainer(ctx, originalName, createCfg)
	if err != nil {
		_ = u.rollbackPreserved(ctx, insp.ID, originalName, preservedName, "", res.SnapshotID, hctx, opts.RollbackHook, hookRunner, logger)
		res.RolledBack = true
		res.Err = fmt.Errorf("create new: %w", err)
		return res
	}
	res.NewContainerID = newID

	// --- 6. Start the new container ----------------------------------------
	if err := u.Docker.StartContainer(ctx, newID); err != nil {
		_ = u.rollbackPreserved(ctx, insp.ID, originalName, preservedName, newID, res.SnapshotID, hctx, opts.RollbackHook, hookRunner, logger)
		res.RolledBack = true
		res.Err = fmt.Errorf("start new: %w", err)
		return res
	}

	// --- 7. Health verification --------------------------------------------
	// Honour the container's own Docker HEALTHCHECK start_period when one
	// is defined: services that take 60s to come up shouldn't be rolled
	// back because Bulwark's 5s daemon default fired too early. The
	// per-container value is read from the inspect we already did in
	// step 2, so there's no extra Docker round-trip.
	graceOverride, _ := insp.HealthcheckStartPeriod()
	healthy, finalStatus, healthErr := u.waitForHealthy(ctx, newID, graceOverride)
	res.HealthStatus = finalStatus
	if !healthy {
		_ = u.rollbackPreserved(ctx, insp.ID, originalName, preservedName, newID, res.SnapshotID, hctx, opts.RollbackHook, hookRunner, logger)
		res.RolledBack = true
		if healthErr != nil {
			res.Err = fmt.Errorf("health: %w", healthErr)
		} else {
			res.Err = fmt.Errorf("health check failed: status=%s", finalStatus)
		}
		return res
	}

	// --- 8. Cleanup: remove the preserved old container + snapshot --------
	if err := u.Docker.RemoveContainer(ctx, insp.ID, true); err != nil {
		// We don't roll back here — the new container is healthy. Leaving
		// the old one around as orphan is recoverable; the user can
		// `docker rm` it manually. Surface as a non-fatal warning.
		logger.Warn("updater: failed to remove preserved old container", "id", insp.ID, "err", err)
	}
	u.tryDestroySnapshot(ctx, &res, logger)

	// --- 9. Post-update hook -----------------------------------------------
	// The new container is healthy, the old has been cleaned up. Failure
	// of this hook is logged but does NOT roll back — the update is done.
	if opts.PostUpdateHook != "" {
		hctx.Action = hooks.ActionPostUpdate
		hctx.NewDigest = "" // populated by callers when known
		hooks.Invoke(ctx, hookRunner, opts.PostUpdateHook, hctx, logger)
	}
	logger.Info("updater: update applied", "container", originalName, "new_id", newID, "old_id", insp.ID)
	return res
}

// trimHookOutput is a tiny helper for surfacing hook stdout/stderr in
// log lines without dumping kilobytes.
func trimHookOutput(b []byte) string {
	if len(b) > 256 {
		return strings.TrimSpace(string(b[:256])) + "..."
	}
	return strings.TrimSpace(string(b))
}

// tryDestroySnapshot is a best-effort cleanup of a successfully-applied
// or aborted snapshot. Failures are warnings, never fatal — the data has
// already been preserved by the rollback / has been superseded by a
// successful update.
func (u *Updater) tryDestroySnapshot(ctx context.Context, res *Result, logger *slog.Logger) {
	if u.Snapshots == nil || res.SnapshotID == "" {
		return
	}
	if err := u.Snapshots.Destroy(ctx, res.SnapshotID); err != nil {
		logger.Warn("updater: failed to destroy filesystem snapshot", "id", res.SnapshotID, "err", err)
	}
}

// rollbackPreserved reverses a partially-completed update. The new
// container (if created) is removed; the filesystem snapshot (if taken)
// is restored; the preserved old container is renamed back to its
// original name and started; finally the rollback hook (if any) fires.
//
// Order matters: restore the FS snapshot BEFORE starting the old container
// so it sees the rolled-back state of its volumes. The old container itself
// is unchanged by the snapshot restore — we're rolling back the data.
func (u *Updater) rollbackPreserved(ctx context.Context, oldID, originalName, preservedName, newID, snapshotID string, hctx hooks.Context, rollbackHook string, hookRunner hooks.Runner, logger *slog.Logger) error {
	logger.Warn("updater: rolling back", "old_id", oldID, "new_id", newID, "snapshot", snapshotID)

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
	if u.Snapshots != nil && snapshotID != "" {
		if err := u.Snapshots.Restore(rbCtx, snapshotID); err != nil {
			rbErrs = append(rbErrs, "restore snapshot: "+err.Error())
		} else {
			logger.Info("updater: filesystem snapshot restored", "id", snapshotID)
		}
	}
	if err := u.Docker.RenameContainer(rbCtx, oldID, originalName); err != nil {
		rbErrs = append(rbErrs, "rename old back: "+err.Error())
	}
	if err := u.Docker.StartContainer(rbCtx, oldID); err != nil {
		rbErrs = append(rbErrs, "start old: "+err.Error())
	}

	// Rollback hook fires AFTER the old container is back online — gives
	// users a clean signal that the rollback completed (page on-call,
	// log to a tracking system, etc.). Failures here are non-fatal; we've
	// already done the dangerous part.
	if rollbackHook != "" && hookRunner != nil {
		hctx.Action = hooks.ActionRollback
		hctx.SnapshotID = snapshotID
		hooks.Invoke(rbCtx, hookRunner, rollbackHook, hctx, logger)
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
func (u *Updater) waitForHealthy(ctx context.Context, id string, graceOverride time.Duration) (bool, docker.HealthStatus, error) {
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
	// Per-container HEALTHCHECK start_period takes precedence over the
	// daemon-wide default. We don't clamp downward — a user who set
	// start_period=120s in their compose file knows their service.
	if graceOverride > 0 {
		grace = graceOverride
		// The ceiling on patience is the overall HealthTimeout. If the
		// declared start_period is longer than the configured timeout,
		// stretch the timeout to at least cover the start_period plus
		// one polling interval — otherwise we'd guarantee a rollback for
		// any container with a long startup probe.
		if minTimeout := graceOverride + interval; timeout < minTimeout {
			timeout = minTimeout
		}
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
