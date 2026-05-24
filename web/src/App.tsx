import { Suspense, lazy } from "react";
import { Route, Routes } from "react-router-dom";
import { AppShell } from "@/components/AppShell";
import { RequireAuth } from "@/components/RequireAuth";
import { Spinner } from "@/components/ui/Spinner";
import Dashboard from "@/pages/Dashboard";
import History from "@/pages/History";
import Login from "@/pages/Login";
import Queue from "@/pages/Queue";

// Long-tail routes: visited second or rarely by an authenticated
// operator, so their bundles get fetched on demand. The eager set
// above (Login + Dashboard + Queue + History + shell chrome) is the
// first-paint + high-frequency surface.
const Audit = lazy(() => import("@/pages/Audit"));
const Containers = lazy(() => import("@/pages/Containers"));
const HistoryDetail = lazy(() => import("@/pages/HistoryDetail"));
const Notifiers = lazy(() => import("@/pages/Notifiers"));
const Settings = lazy(() => import("@/pages/Settings"));
const Snapshots = lazy(() => import("@/pages/Snapshots"));

const lazyFallback = (
  <div className="flex min-h-[60vh] items-center justify-center">
    <Spinner />
  </div>
);

/**
 * Top-level routes. The shell layout wraps every authenticated route
 * via the AppShell <Outlet />, so nav + sign-out + the inner
 * <Outlet /> all live in one place. Lazy routes share a single
 * Suspense boundary so a chunk-fetch-in-flight shows one spinner
 * rather than each route flashing its own.
 */
export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        element={
          <RequireAuth>
            <AppShell />
          </RequireAuth>
        }
      >
        <Route index element={<Dashboard />} />
        <Route path="queue" element={<Queue />} />
        <Route path="history" element={<History />} />
        <Route
          path="history/:id"
          element={
            <Suspense fallback={lazyFallback}>
              <HistoryDetail />
            </Suspense>
          }
        />
        <Route
          path="containers"
          element={
            <Suspense fallback={lazyFallback}>
              <Containers />
            </Suspense>
          }
        />
        <Route
          path="notifiers"
          element={
            <Suspense fallback={lazyFallback}>
              <Notifiers />
            </Suspense>
          }
        />
        <Route
          path="snapshots"
          element={
            <Suspense fallback={lazyFallback}>
              <Snapshots />
            </Suspense>
          }
        />
        <Route
          path="audit"
          element={
            <Suspense fallback={lazyFallback}>
              <Audit />
            </Suspense>
          }
        />
        <Route
          path="settings"
          element={
            <Suspense fallback={lazyFallback}>
              <Settings />
            </Suspense>
          }
        />
        <Route path="*" element={<Dashboard />} />
      </Route>
    </Routes>
  );
}
