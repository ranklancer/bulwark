import { useCallback, useEffect, useState } from "react";
import { api, apiJson } from "./api";
import type {
  AuditEvent,
  ClassificationOverride,
  ContainerEntry,
  EffectiveConfigResponse,
  HostInfo,
  NotifierCreateRequest,
  NotifierEntry,
  NotifierEntryDetail,
  QueueRow,
  ScanRecord,
  ScheduleOverride,
  SettingsResponse,
  SnapshotEntry,
} from "./types";

interface AsyncResource<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  refresh: () => Promise<void>;
}

/**
 * useResource wraps the common "fetch JSON, surface loading/error/data,
 * support manual refresh" pattern. We deliberately don't introduce
 * TanStack Query yet (deferred to 16f when WebSocket invalidation
 * justifies the dep) — for read-mostly pages a useEffect is enough.
 */
function useResource<T>(path: string): AsyncResource<T> {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const body = await apiJson<T>(path);
      setData(body);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [path]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return { data, loading, error, refresh };
}

export function useScansList(limit = 20) {
  return useResource<ScanRecord[]>(`/scans?limit=${limit}`);
}

export function useScan(id: string | undefined) {
  // The /scans/latest path resolves to the most recent scan; useful
  // for the Dashboard's "current state" card. Caller passes "latest"
  // explicitly when that's what they want.
  const path = id ? `/scans/${encodeURIComponent(id)}` : "";
  const [data, setData] = useState<ScanRecord | null>(null);
  const [loading, setLoading] = useState(Boolean(id));
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    if (!id) {
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const body = await apiJson<ScanRecord>(path);
      setData(body);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [id, path]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return { data, loading, error, refresh };
}

export function useQueue() {
  return useResource<QueueRow[]>("/queue");
}

/**
 * useDecide submits an approval / rejection. The optimistic refresh
 * happens inside the page calling it: we can't auto-refresh queue here
 * because the hook doesn't own the queue state.
 */
export function useDecide() {
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const decide = useCallback(
    async (params: {
      container: string;
      decision: "approved" | "rejected";
      note?: string;
      decidedBy?: string;
    }) => {
      setSubmitting(true);
      setError(null);
      try {
        const res = await api("/queue", {
          method: "POST",
          body: JSON.stringify({
            container: params.container,
            decision: params.decision,
            note: params.note ?? "",
            decided_by: params.decidedBy ?? "dashboard",
          }),
        });
        if (!res.ok) {
          const body = await res.text();
          throw new Error(`HTTP ${res.status}: ${body}`);
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        setError(msg);
        throw err;
      } finally {
        setSubmitting(false);
      }
    },
    [],
  );

  return { decide, submitting, error };
}

export function useAudit(limit = 200) {
  return useResource<AuditEvent[]>(`/audit?limit=${limit}`);
}

export function useNotifiers() {
  return useResource<NotifierEntry[]>("/notifiers");
}

export function useContainers() {
  return useResource<ContainerEntry[]>("/containers");
}

export function useConfig() {
  return useResource<unknown>("/config");
}

export function usePolicies() {
  return useResource<{ classifier: unknown; overrides: unknown }>("/policies");
}

export function useSnapshots(target: string) {
  // Empty target → don't fetch (the page renders an "enter a target"
  // prompt). useResource keys on the path string, so passing empty
  // means we just don't call.
  const path = target ? `/snapshots?target=${encodeURIComponent(target)}` : "";
  const [data, setData] = useState<SnapshotEntry[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    if (!target) {
      setData(null);
      setLoading(false);
      setError(null);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const body = await apiJson<SnapshotEntry[]>(path);
      setData(body);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [target, path]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return { data, loading, error, refresh };
}

/**
 * useCreateNotifier wraps POST /api/v1/notifiers. The server validates
 * the per-kind required fields and returns 400 with a human-readable
 * message on rejection (URL malformed, missing webhook, etc.); the
 * caller renders the message inline below the form.
 */
export function useCreateNotifier() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const create = useCallback(async (req: NotifierCreateRequest): Promise<NotifierEntry> => {
    setBusy(true);
    setError(null);
    try {
      const res = await api("/notifiers", {
        method: "POST",
        body: JSON.stringify(req),
      });
      if (!res.ok) {
        const body = await res.text();
        throw new Error(extractError(body, res.status));
      }
      return (await res.json()) as NotifierEntry;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
      throw err;
    } finally {
      setBusy(false);
    }
  }, []);

  return { create, busy, error };
}

/**
 * useDeleteNotifier wraps DELETE /api/v1/notifiers/{id}. Yaml-defined
 * notifiers are not deletable via the dashboard (operator edits the
 * yaml and restarts); the UI hides the delete button for source=yaml
 * cards.
 */
export function useDeleteNotifier() {
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const remove = useCallback(async (id: string) => {
    setBusy(id);
    setError(null);
    try {
      const res = await api(`/notifiers/${encodeURIComponent(id)}`, {
        method: "DELETE",
      });
      if (!res.ok) {
        const body = await res.text();
        throw new Error(extractError(body, res.status));
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
      throw err;
    } finally {
      setBusy(null);
    }
  }, []);

  return { remove, busy, error };
}

/**
 * useTestEphemeralNotifier wraps POST /api/v1/notifiers/test. Lets the
 * operator confirm a webhook works before saving the config: the
 * daemon builds an in-memory notifier from the request body, dispatches
 * a synthetic event, then drops it.
 */
export function useTestEphemeralNotifier() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ok, setOk] = useState(false);

  const send = useCallback(async (req: NotifierCreateRequest) => {
    setBusy(true);
    setError(null);
    setOk(false);
    try {
      const res = await api("/notifiers/test", {
        method: "POST",
        body: JSON.stringify(req),
      });
      if (!res.ok) {
        const body = await res.text();
        throw new Error(extractError(body, res.status));
      }
      setOk(true);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
    } finally {
      setBusy(false);
    }
  }, []);

  return { send, busy, error, ok };
}

/**
 * useUpdateNotifier wraps PATCH /api/v1/notifiers/{id} for editing
 * an existing UI-managed notifier. Yaml-defined notifiers cannot be
 * updated via this API.
 */
export function useUpdateNotifier() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const update = useCallback(async (id: string, req: NotifierCreateRequest): Promise<NotifierEntry> => {
    setBusy(true);
    setError(null);
    try {
      const res = await api(`/notifiers/${encodeURIComponent(id)}`, {
        method: "PATCH",
        body: JSON.stringify(req),
      });
      if (!res.ok) {
        const body = await res.text();
        throw new Error(extractError(body, res.status));
      }
      return (await res.json()) as NotifierEntry;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
      throw err;
    } finally {
      setBusy(false);
    }
  }, []);

  return { update, busy, error };
}

/**
 * useNotifierDetail fetches the full editable shape of a single
 * UI-managed notifier (used to pre-fill the edit form).
 */
export function useNotifierDetail(id: string | null) {
  const [data, setData] = useState<NotifierEntryDetail | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) {
      setData(null);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    (async () => {
      try {
        const body = await apiJson<NotifierEntryDetail>(`/notifiers/${encodeURIComponent(id)}`);
        if (!cancelled) setData(body);
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [id]);

  return { data, loading, error };
}

/**
 * useSettings wraps GET /api/v1/config/settings and returns both the
 * current override payload and the section metadata (restart-required
 * etc.) the dashboard needs to render tabs + banners.
 */
export function useSettings() {
  return useResource<SettingsResponse>("/config/settings");
}

/**
 * useEffectiveConfig returns the post-merge yaml-style tree (with
 * secrets redacted) for the Settings page's "Advanced YAML" view.
 */
export function useEffectiveConfig() {
  return useResource<EffectiveConfigResponse>("/config/effective");
}

/**
 * useHost returns the daemon's host detection result (platform,
 * capabilities, suggested backend, configured backend).
 */
export function useHost() {
  return useResource<HostInfo>("/host");
}

/**
 * usePatchSettings issues PATCH /api/v1/config/{section}. Each call
 * applies a partial section update — the server merges with what's
 * already persisted, so the caller only sends fields that changed.
 */
export function usePatchSettings() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const patch = useCallback(async (
    section: "schedule" | "classification",
    body: ScheduleOverride | ClassificationOverride,
  ): Promise<SettingsResponse> => {
    setBusy(true);
    setError(null);
    try {
      const res = await api(`/config/${encodeURIComponent(section)}`, {
        method: "PATCH",
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(extractError(text, res.status));
      }
      return (await res.json()) as SettingsResponse;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
      throw err;
    } finally {
      setBusy(false);
    }
  }, []);

  return { patch, busy, error };
}

function extractError(body: string, fallbackStatus: number): string {
  try {
    const parsed = JSON.parse(body) as { error?: string };
    if (parsed.error) return parsed.error;
  } catch {
    /* not JSON */
  }
  return `HTTP ${fallbackStatus}: ${body || "request failed"}`;
}

export function useTestNotifier() {
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const send = useCallback(async (name: string) => {
    setBusy(name);
    setError(null);
    try {
      const res = await api(`/notifiers/${encodeURIComponent(name)}/test`, {
        method: "POST",
        body: "{}",
      });
      if (!res.ok) {
        const body = await res.text();
        throw new Error(`HTTP ${res.status}: ${body}`);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
      throw err;
    } finally {
      setBusy(null);
    }
  }, []);

  return { send, busy, error };
}

export function useTriggerScan() {
  const [triggering, setTriggering] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const trigger = useCallback(async () => {
    setTriggering(true);
    setError(null);
    try {
      const res = await api("/scans", { method: "POST", body: "{}" });
      if (!res.ok && res.status !== 202) {
        const body = await res.text();
        throw new Error(`HTTP ${res.status}: ${body}`);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
      throw err;
    } finally {
      setTriggering(false);
    }
  }, []);

  return { trigger, triggering, error };
}
