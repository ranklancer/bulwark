import { Navigate, useLocation } from "react-router-dom";
import { useAuth } from "@/lib/auth";
import type { ReactNode } from "react";

/**
 * RequireAuth gates the authenticated routes. While the auth probe is
 * in flight we show a minimal spinner so the user doesn't see a flash
 * of redirect-to-login. On unauthenticated, redirect to /login and
 * remember the intended destination so the login page can return
 * users to where they were headed.
 */
export function RequireAuth({ children }: { children: ReactNode }) {
  const { status } = useAuth();
  const location = useLocation();

  if (status === "loading") {
    return (
      <div className="flex min-h-screen items-center justify-center text-muted-foreground">
        <span className="text-sm">Loading…</span>
      </div>
    );
  }
  if (status === "unauthenticated") {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }
  return <>{children}</>;
}
