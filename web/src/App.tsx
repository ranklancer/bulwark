import { Route, Routes } from "react-router-dom";
import { AppShell } from "@/components/AppShell";
import { RequireAuth } from "@/components/RequireAuth";
import Audit from "@/pages/Audit";
import Containers from "@/pages/Containers";
import Dashboard from "@/pages/Dashboard";
import History from "@/pages/History";
import HistoryDetail from "@/pages/HistoryDetail";
import Login from "@/pages/Login";
import Notifiers from "@/pages/Notifiers";
import Queue from "@/pages/Queue";
import Settings from "@/pages/Settings";
import Snapshots from "@/pages/Snapshots";

/**
 * Top-level routes. The shell layout wraps every authenticated route
 * via the AppShell <Outlet />, so nav + sign-out + the inner
 * <Outlet /> all live in one place.
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
        <Route path="history/:id" element={<HistoryDetail />} />
        <Route path="containers" element={<Containers />} />
        <Route path="notifiers" element={<Notifiers />} />
        <Route path="snapshots" element={<Snapshots />} />
        <Route path="audit" element={<Audit />} />
        <Route path="settings" element={<Settings />} />
        <Route path="*" element={<Dashboard />} />
      </Route>
    </Routes>
  );
}
