import { cn } from "@/lib/utils";

// Phase 16a — minimal scaffold. This proves Vite + React + Tailwind +
// the cn() helper all wire up. Real pages land in 16c (Dashboard /
// Queue / History) once 16b's session auth is in place.
export default function App() {
  return (
    <main className="min-h-screen bg-background text-foreground antialiased">
      <div className={cn("mx-auto max-w-3xl px-6 py-16")}>
        <h1 className="text-4xl font-semibold tracking-tight">Bulwark</h1>
        <p className="mt-3 text-muted-foreground">
          Dashboard scaffolding. The full UI lands across phases 16b–16f;
          for now the existing dashboard is mounted at{" "}
          <a className="underline underline-offset-4" href="/legacy/">
            /legacy/
          </a>
          .
        </p>
        <ul className="mt-8 space-y-2 text-sm">
          <li>
            <span className="text-muted-foreground">API:</span>{" "}
            <code className="rounded bg-muted px-1.5 py-0.5">/api/v1/*</code>
          </li>
          <li>
            <span className="text-muted-foreground">Health:</span>{" "}
            <code className="rounded bg-muted px-1.5 py-0.5">/health</code>
          </li>
          <li>
            <span className="text-muted-foreground">Metrics:</span>{" "}
            <code className="rounded bg-muted px-1.5 py-0.5">/metrics</code>
          </li>
        </ul>
      </div>
    </main>
  );
}
