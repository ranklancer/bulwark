import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { api, apiJson, setOnUnauthorized } from "./api";

/**
 * Authentication state machine:
 *
 *   loading        — initial probe in flight; render a spinner
 *   authenticated  — probe returned 200; render the dashboard
 *   unauthenticated — probe returned 401 OR a logout/401 fired later
 */
export type AuthStatus = "loading" | "authenticated" | "unauthenticated";

interface SessionProbeResponse {
  authenticated: boolean;
  session_endpoints_enabled: boolean;
}

interface AuthContextValue {
  status: AuthStatus;
  /**
   * True when the daemon has POST/DELETE /api/v1/sessions wired up.
   * False when the daemon is in anonymous mode (in which case the
   * dashboard hides login + logout UX entirely).
   */
  sessionEndpointsEnabled: boolean;
  /** Last login error message, surfaced by the Login page. */
  loginError: string | null;
  /** Trade a bearer token for a session cookie. */
  login: (bearerToken: string) => Promise<void>;
  /** Drop the session cookie + flip back to unauthenticated. */
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

/**
 * useAuth is the hook every page or guard component reaches for.
 * Throws when used outside an AuthProvider — this is intentional;
 * the alternative (silently returning a default) would mask wiring
 * bugs and make the dashboard appear logged-out for confusing reasons.
 */
export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth: must be used inside <AuthProvider>");
  }
  return ctx;
}

/**
 * AuthProvider manages session state. On mount it probes
 * GET /api/v1/sessions:
 *   - 200 → authenticated. Read the body to learn whether
 *     session endpoints are available.
 *   - 401 → unauthenticated. The route guard will redirect to /login.
 *   - other → tolerated as unauthenticated; user retries via the
 *     login form, which surfaces the actual error.
 */
export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<AuthStatus>("loading");
  const [sessionEndpointsEnabled, setSessionEndpointsEnabled] = useState(false);
  const [loginError, setLoginError] = useState<string | null>(null);

  // Wire the api.ts 401 hook so any subsequent 401 (e.g., session
  // expiry mid-page) flips state back to unauthenticated. The
  // RequireAuth guard takes it from there.
  useEffect(() => {
    setOnUnauthorized(() => setStatus("unauthenticated"));
  }, []);

  // Initial session probe.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const body = await apiJson<SessionProbeResponse>("/sessions");
        if (cancelled) return;
        setSessionEndpointsEnabled(Boolean(body.session_endpoints_enabled));
        setStatus("authenticated");
      } catch (err) {
        if (cancelled) return;
        // 401 was already routed through onUnauthorized; this just
        // ensures status is set even on initial probe error.
        setStatus("unauthenticated");
        // Quietly absorb non-401 errors at startup — login flow
        // surfaces a precise reason if the user tries to log in.
        void err;
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const login = useCallback(async (bearerToken: string) => {
    setLoginError(null);
    const res = await api("/sessions", {
      method: "POST",
      headers: { Authorization: `Bearer ${bearerToken}` },
      body: "{}",
    });
    if (res.ok) {
      // Refresh probe so sessionEndpointsEnabled reflects the new state.
      try {
        const body = await apiJson<SessionProbeResponse>("/sessions");
        setSessionEndpointsEnabled(Boolean(body.session_endpoints_enabled));
      } catch {
        // Probe refresh failure is non-fatal: the cookie is set
        // and the dashboard will hit endpoints normally.
      }
      setStatus("authenticated");
      return;
    }
    if (res.status === 401) {
      setLoginError("Invalid bearer token.");
    } else {
      setLoginError(`Login failed: HTTP ${res.status} ${res.statusText}`);
    }
    // Re-throw so the caller can choose to await + handle.
    throw new Error(`login failed: ${res.status}`);
  }, []);

  const logout = useCallback(async () => {
    try {
      await api("/sessions", { method: "DELETE" });
    } catch {
      // Network errors during logout shouldn't strand the user on
      // the dashboard — fall through to the state update.
    }
    setStatus("unauthenticated");
  }, []);

  return (
    <AuthContext.Provider
      value={{ status, sessionEndpointsEnabled, loginError, login, logout }}
    >
      {children}
    </AuthContext.Provider>
  );
}
