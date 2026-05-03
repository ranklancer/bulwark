import { useState } from "react";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody, CardDescription, CardHeader, CardTitle } from "@/components/ui/Card";
import { Spinner } from "@/components/ui/Spinner";
import { useNotifiers, useTestNotifier } from "@/lib/hooks";

/**
 * Notifiers lists the dispatcher's configured channels and lets the
 * operator fire a synthetic test event into one of them. The Notify
 * call uses the daemon's same path the CLI's `bulwark notify-test`
 * uses, so what shows up in Slack/Discord/etc. matches what real
 * alerts will look like.
 */
export default function Notifiers() {
  const { data, loading, error, refresh } = useNotifiers();
  const { send, busy, error: sendError } = useTestNotifier();
  const [lastSent, setLastSent] = useState<string | null>(null);

  async function onTest(name: string) {
    setLastSent(null);
    try {
      await send(name);
      setLastSent(name);
    } catch {
      // sendError surfaces in the card.
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Notifiers</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Configured channels and their thresholds. Use “Send test” to fire a
          synthetic event end-to-end — the synthetic flag bypasses every
          channel's own MinLevel filter so the test always reaches its
          destination.
        </p>
      </div>

      {sendError ? (
        <p className="text-sm text-red-600" role="alert">
          {sendError}
        </p>
      ) : null}
      {lastSent ? (
        <p className="text-sm text-emerald-700 dark:text-emerald-400">
          Test event sent to <code>{lastSent}</code>.
        </p>
      ) : null}

      {loading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : error ? (
        <p className="text-sm text-red-600">{error}</p>
      ) : !data?.length ? (
        <Card>
          <CardBody>
            <p className="text-sm text-muted-foreground">
              No notifiers configured. Add a Slack / Discord / SMTP / Home
              Assistant block to <code>notifications</code> in your
              <code>bulwark.yaml</code> and restart the daemon.
            </p>
          </CardBody>
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          {data.map((n) => (
            <Card key={n.name}>
              <CardHeader>
                <CardTitle>{n.name}</CardTitle>
                <CardDescription>
                  Min level <Badge tone="info">{n.min_level}</Badge>
                </CardDescription>
              </CardHeader>
              <CardBody className="flex items-center justify-between gap-3">
                <div className="text-xs text-muted-foreground">
                  Test events use the synthetic flag and ignore the channel's
                  level threshold.
                </div>
                <Button
                  size="sm"
                  variant="primary"
                  onClick={() => onTest(n.name)}
                  disabled={busy === n.name}
                >
                  {busy === n.name ? <Spinner /> : null}
                  Send test
                </Button>
              </CardBody>
            </Card>
          ))}
        </div>
      )}

      <div className="text-right">
        <Button size="sm" variant="ghost" onClick={() => void refresh()}>
          Refresh
        </Button>
      </div>
    </div>
  );
}
