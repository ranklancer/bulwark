// Tiny fetch wrapper for the Bulwark dashboard. All requests:
//
//   * Are prefixed with /api/v1 (the daemon's stable API surface).
//   * Carry credentials so the HttpOnly session cookie travels.
//   * Notify the AuthProvider on 401 so it can flip auth state +
//     trigger a redirect to /login.
//
// The 401 callback indirection avoids a dependency cycle: api.ts is
// imported by hooks and pages, the AuthProvider registers itself
// with this module via setOnUnauthorized at mount time.

let onUnauthorized: () => void = () => {};

/**
 * Register the AuthProvider's "set unauthenticated" callback.
 * Idempotent — calling again replaces the previous registration.
 */
export function setOnUnauthorized(fn: () => void) {
  onUnauthorized = fn;
}

export interface ApiError extends Error {
  status: number;
  body?: unknown;
}

/**
 * Wrap window.fetch with the Bulwark conventions. The path is relative
 * to the /api/v1 prefix — pass "/scans", not "/api/v1/scans". When the
 * server returns 401 the registered callback fires before the response
 * is returned to the caller.
 *
 * The returned Response is otherwise unchanged; callers decode it.
 */
export async function api(path: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  if (!headers.has("Content-Type") && init.body !== undefined) {
    headers.set("Content-Type", "application/json");
  }
  const res = await fetch(`/api/v1${path}`, {
    ...init,
    credentials: "include",
    headers,
  });
  if (res.status === 401) {
    onUnauthorized();
  }
  return res;
}

/**
 * Convenience wrapper that decodes JSON and throws an ApiError on
 * non-2xx responses. Use this when you only care about the success
 * path; for finer-grained control (e.g. interpreting 404 as "no
 * scans yet") fall back to the raw `api()` call.
 */
export async function apiJson<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await api(path, init);
  if (!res.ok) {
    let body: unknown = undefined;
    try {
      body = await res.json();
    } catch {
      // Non-JSON bodies are tolerable here.
    }
    const err = new Error(`HTTP ${res.status} ${res.statusText}`) as ApiError;
    err.status = res.status;
    err.body = body;
    throw err;
  }
  return (await res.json()) as T;
}
