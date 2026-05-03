import { useEffect } from "react";

/**
 * Stable event-type names. Keep in sync with internal/api/events.go's
 * Event* constants. The dashboard switches on these to decide which
 * data resources to invalidate.
 */
export const EventTypes = {
  ScanCompleted: "scan.completed",
  DecisionRecorded: "decision.recorded",
  DecisionForgot: "decision.forgot",
  ApplySuccess: "apply.success",
  ApplyFailed: "apply.failed",
  ApplyRolledBack: "apply.rolled_back",
  ApplyStackSkipped: "apply.stack_skipped",
  NotificationsCleared: "notifications.cleared",
} as const;

export type EventType = (typeof EventTypes)[keyof typeof EventTypes];

interface ServerEvent {
  type: string;
  time: string;
  container?: string;
  image?: string;
  scan_id?: string;
  detail?: string;
  extra?: Record<string, unknown>;
}

type Listener = (e: ServerEvent) => void;

// Module-level singleton — exactly one EventSource lives across the
// dashboard's lifetime so multiple components subscribing to events
// share the same TCP/HTTP/2 stream. The connection auto-reconnects
// via the standard EventSource behaviour; we only manage the
// listener fan-out.
let source: EventSource | null = null;
const listeners = new Set<Listener>();

function ensureConnected() {
  if (source) return;
  if (typeof EventSource === "undefined") return; // SSR-safe.
  // The browser's EventSource sends cookies automatically when the
  // connection target is same-origin (we serve the dashboard from
  // the same daemon). withCredentials only matters for cross-origin
  // setups; same-origin = always sent.
  source = new EventSource("/api/v1/events");
  source.onmessage = handle;
  // Specific named events still arrive on .onmessage when the event
  // line doesn't have a corresponding addEventListener — but Bulwark's
  // server emits explicit "event:" lines, so we attach a default
  // listener via addEventListener("error") for connection feedback
  // and let onmessage swallow the rest. The catch-all is below.
  for (const eventName of Object.values(EventTypes)) {
    source.addEventListener(eventName, handle);
  }
}

function handle(ev: MessageEvent) {
  try {
    const data = JSON.parse(ev.data) as ServerEvent;
    listeners.forEach((fn) => fn(data));
  } catch {
    // Heartbeats / hello comments don't carry JSON; ignore.
  }
}

/**
 * useLiveEvents subscribes a listener to the live event stream. Pass
 * a filter array of event type names to receive only those; pass
 * undefined to receive every event.
 *
 * Auto-establishes the underlying EventSource on first call across
 * the entire app, and tears it down when the last listener
 * unsubscribes — so an anonymous-mode deployment that never gets a
 * 401 still cleans up properly when the user navigates away.
 */
export function useLiveEvents(types: EventType[] | undefined, fn: (e: ServerEvent) => void) {
  useEffect(() => {
    const filter = types ? new Set<string>(types) : null;
    const wrapped: Listener = (e) => {
      if (filter && !filter.has(e.type)) return;
      fn(e);
    };
    listeners.add(wrapped);
    ensureConnected();
    return () => {
      listeners.delete(wrapped);
      if (listeners.size === 0 && source) {
        source.close();
        source = null;
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fn, types?.join("|")]);
}

/**
 * useLiveRefresh wires a refresh() function (typically from the
 * useResource hooks) to one or more event types — when any matches,
 * the resource is refetched. The dashboard's Dashboard / Queue /
 * History pages now stay in sync with the daemon without
 * manually-triggered refresh.
 */
export function useLiveRefresh(types: EventType[], refresh: () => void) {
  useLiveEvents(types, () => {
    refresh();
  });
}
