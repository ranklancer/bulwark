import { Route, Routes } from "react-router-dom";
import { AppShell } from "@/components/AppShell";
import { RequireAuth } from "@/components/RequireAuth";
import Dashboard from "@/pages/Dashboard";
import History from "@/pages/History";
import HistoryDetail from "@/pages/HistoryDetail";
import Login from "@/pages/Login";
import Queue from "@/pages/Queue";

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
        <Route path="*" element={<Dashboard />} />
      </Route>
    </Routes>
  );
}
