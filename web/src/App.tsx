import { Route, Routes } from "react-router-dom";
import { RequireAuth } from "@/components/RequireAuth";
import Dashboard from "@/pages/Dashboard";
import Login from "@/pages/Login";

/**
 * Top-level routes. The route table stays minimal until 16c starts
 * adding real pages.
 *
 *   /login   — public; the bearer-token form.
 *   /*       — authenticated; the dashboard. RequireAuth handles the
 *              redirect-to-login on unauthenticated state.
 */
export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        path="*"
        element={
          <RequireAuth>
            <Dashboard />
          </RequireAuth>
        }
      />
    </Routes>
  );
}
