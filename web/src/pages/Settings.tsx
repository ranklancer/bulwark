import { Card, CardBody, CardDescription, CardHeader, CardTitle } from "@/components/ui/Card";
import { useConfig, usePolicies } from "@/lib/hooks";

/**
 * Settings is read-only by design (16e contract). Two side-by-side
 * panels — the loaded YAML rendered as redacted JSON, and the
 * effective classifier policies after merge. Operators get visibility
 * into "what does the daemon think it sees?" without having to shell
 * into the host.
 *
 * Editing endpoints are explicitly out of scope: validation,
 * restart-or-hot-reload semantics, file permissions, and multi-user
 * race conditions all deserve their own phase.
 */
export default function Settings() {
  const config = useConfig();
  const policies = usePolicies();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Settings</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Loaded YAML + effective classifier policies. Read-only — edit your
          <code className="mx-1 rounded bg-muted px-1.5 py-0.5">bulwark.yaml</code>
          on the host and restart to apply changes.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Configuration</CardTitle>
          <CardDescription>
            Tokens, webhook URLs, passwords, and HMAC secrets are redacted to
            <code className="ml-1 rounded bg-muted px-1.5 py-0.5">"***"</code>.
          </CardDescription>
        </CardHeader>
        <CardBody>
          {config.loading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : config.error ? (
            <p className="text-sm text-red-600">
              {config.error.includes("404")
                ? "Daemon was started without a config file (--config flag unset). No YAML to display."
                : config.error}
            </p>
          ) : (
            <pre className="overflow-x-auto rounded-md bg-muted p-3 font-mono text-xs leading-relaxed">
              {JSON.stringify(config.data, null, 2)}
            </pre>
          )}
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Effective policies</CardTitle>
          <CardDescription>
            Classifier defaults merged with config overrides. Per-stack and
            per-container overrides surface in the second block.
          </CardDescription>
        </CardHeader>
        <CardBody className="space-y-3">
          {policies.loading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : policies.error ? (
            <p className="text-sm text-red-600">{policies.error}</p>
          ) : (
            <>
              <section>
                <h3 className="text-sm font-medium">Classifier</h3>
                <pre className="mt-1 overflow-x-auto rounded-md bg-muted p-3 font-mono text-xs leading-relaxed">
                  {JSON.stringify(policies.data?.classifier, null, 2)}
                </pre>
              </section>
              <section>
                <h3 className="text-sm font-medium">Overrides</h3>
                <pre className="mt-1 overflow-x-auto rounded-md bg-muted p-3 font-mono text-xs leading-relaxed">
                  {JSON.stringify(policies.data?.overrides, null, 2)}
                </pre>
              </section>
            </>
          )}
        </CardBody>
      </Card>
    </div>
  );
}
