import { useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useAuth } from "@/lib/auth";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/Button";

interface NavItem {
  to: string;
  label: string;
  end?: boolean;
}

const NAV: NavItem[] = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/queue", label: "Queue" },
  { to: "/history", label: "History" },
  { to: "/containers", label: "Containers" },
  { to: "/notifiers", label: "Notifiers" },
  { to: "/snapshots", label: "Snapshots" },
  { to: "/audit", label: "Audit" },
  { to: "/settings", label: "Settings" },
];

/**
 * AppShell is the top-level layout for authenticated routes. The
 * <Outlet /> renders whichever child route matches. Nav uses NavLink
 * so the active page gets a visual indicator without us tracking
 * location manually.
 */
export function AppShell() {
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
    <div className="min-h-screen bg-background text-foreground antialiased">
      <header className="border-b border-border">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-4 px-6 py-3">
          <span className="text-lg font-semibold">Bulwark</span>
          <nav aria-label="Primary" className="flex items-center gap-1 text-sm">
            {NAV.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) =>
                  cn(
                    "rounded-md px-3 py-1.5 transition",
                    isActive
                      ? "bg-muted font-medium text-foreground"
                      : "text-muted-foreground hover:bg-muted hover:text-foreground",
                  )
                }
              >
                {item.label}
              </NavLink>
            ))}
          </nav>
          <div className="ml-auto flex items-center gap-2 text-sm">
            <a
              href="/legacy/"
              className="text-muted-foreground hover:text-foreground"
            >
              legacy
            </a>
            {sessionEndpointsEnabled ? (
              <Button
                variant="secondary"
                size="sm"
                onClick={onLogout}
                disabled={busy}
              >
                {busy ? "Signing out…" : "Sign out"}
              </Button>
            ) : (
              <span className="text-xs text-muted-foreground">anonymous</span>
            )}
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-6 py-8">
        <Outlet />
      </main>
    </div>
  );
}
