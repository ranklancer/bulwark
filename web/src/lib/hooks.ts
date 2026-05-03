import { useCallback, useEffect, useState } from "react";
import { api, apiJson } from "./api";
import type { AuditEvent, ContainerEntry, NotifierEntry, QueueRow, ScanRecord, SnapshotEntry } from "./types";

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
