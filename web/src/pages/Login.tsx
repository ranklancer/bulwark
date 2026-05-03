import { useState, type FormEvent } from "react";
import { useLocation, useNavigate, type Location } from "react-router-dom";
import { useAuth } from "@/lib/auth";

interface LocationState {
  from?: Location;
}

/**
 * Login is the bearer-token-for-cookie exchange. The token is held
 * only in this component's local state — never persisted to
 * localStorage — and is dropped immediately after a successful POST
 * to /api/v1/sessions issues the HttpOnly session cookie.
 */
export default function Login() {
  const { status, login, loginError } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);

  // If the user is already authenticated (e.g., logged in via a
  // forward-proxy that set Remote-User), bounce them to the
  // dashboard instead of showing a redundant login form.
  if (status === "authenticated") {
    const from = (location.state as LocationState | null)?.from?.pathname ?? "/";
    navigate(from, { replace: true });
    return null;
  }

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!token.trim() || busy) return;
    setBusy(true);
    try {
      await login(token.trim());
      const from = (location.state as LocationState | null)?.from?.pathname ?? "/";
      navigate(from, { replace: true });
    } catch {
      // loginError is set by AuthProvider; component re-renders.
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-background text-foreground">
      <form
        onSubmit={onSubmit}
        className="w-full max-w-sm space-y-6 rounded-lg border border-border bg-background p-6 shadow-sm"
        aria-labelledby="login-title"
      >
        <div>
          <h1 id="login-title" className="text-2xl font-semibold tracking-tight">
            Bulwark
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Sign in with your bearer token. We trade it for an HTTP-only session
            cookie — the token isn't stored in the browser.
          </p>
        </div>
        <label className="block">
          <span className="text-sm font-medium">Bearer token</span>
          <input
            type="password"
            autoFocus
            autoComplete="current-password"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder="••••••••••••••••"
            className="mt-1.5 block w-full rounded-md border border-border bg-background px-3 py-2 text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary"
            aria-required="true"
            disabled={busy || status === "loading"}
          />
        </label>
        {loginError ? (
          <p className="text-sm text-red-600" role="alert">
            {loginError}
          </p>
        ) : null}
        <button
          type="submit"
          disabled={busy || !token.trim() || status === "loading"}
          className="w-full rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground transition disabled:opacity-50"
        >
          {busy ? "Signing in…" : "Sign in"}
        </button>
        <p className="text-xs text-muted-foreground">
          Anonymous deployments don't need this — they bypass login automatically.
        </p>
      </form>
    </main>
  );
}
