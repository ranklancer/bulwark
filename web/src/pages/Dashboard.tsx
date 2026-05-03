import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "@/lib/auth";
import { cn } from "@/lib/utils";

/**
 * Dashboard is a placeholder for Phase 16c's real Dashboard / Queue /
 * History pages. For now it serves three purposes:
 *   1. Visual proof that the auth flow + routing + session cookie work.
 *   2. A logout button — the only auth action available post-login.
 *   3. A pointer to the legacy dashboard at /legacy/ so operators
 *      have somewhere to do real work until 16c lands.
 */
export default function Dashboard() {
  const { logout, sessionEndpointsEnabled } = useAuth();
  const navigate = useNavigate();
  const [busy, setBusy] = useState(false);

  async function onLogout() {
    setBusy(true);
    try {
      await logout();
      navigate("/login", { replace: true });
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="min-h-screen bg-background text-foreground antialiased">
      <header className="border-b border-border">
        <div className={cn("mx-auto flex max-w-5xl items-center justify-between px-6 py-4")}>
          <h1 className="text-xl font-semibold">Bulwark</h1>
          {sessionEndpointsEnabled ? (
            <button
              type="button"
              onClick={onLogout}
              disabled={busy}
              className="rounded-md border border-border px-3 py-1.5 text-sm transition hover:bg-muted disabled:opacity-50"
            >
              {busy ? "Signing out…" : "Sign out"}
            </button>
          ) : (
            <span className="text-xs text-muted-foreground">anonymous mode</span>
          )}
        </div>
      </header>
      <section className="mx-auto max-w-5xl px-6 py-12">
        <h2 className="text-3xl font-semibold tracking-tight">Welcome.</h2>
        <p className="mt-3 text-muted-foreground">
          The full dashboard arrives across phases 16c–16f. Until then, the
          existing tools live at:
        </p>
        <ul className="mt-6 space-y-3 text-sm">
          <li>
            <a
              className="font-medium underline underline-offset-4"
              href="/legacy/"
            >
              /legacy/
            </a>
            <span className="text-muted-foreground"> — the original dashboard</span>
          </li>
          <li>
            <code className="rounded bg-muted px-1.5 py-0.5">/api/v1/*</code>
            <span className="text-muted-foreground"> — the JSON API</span>
          </li>
          <li>
            <code className="rounded bg-muted px-1.5 py-0.5">/metrics</code>
            <span className="text-muted-foreground"> — Prometheus</span>
          </li>
        </ul>
      </section>
    </main>
  );
}
