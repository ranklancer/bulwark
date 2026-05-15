import { useState } from "react";
import { AddNotifierModal } from "@/components/AddNotifierModal";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody, CardDescription, CardHeader, CardTitle } from "@/components/ui/Card";
import { Spinner } from "@/components/ui/Spinner";
import { useDeleteNotifier, useNotifiers, useTestNotifier } from "@/lib/hooks";

/**
 * Notifiers lists the dispatcher's configured channels. UI-managed
 * notifiers (those in the encrypted config store) can be added via
 * the "Add notifier" button and removed via per-card delete. Yaml-
 * defined notifiers surface as read-only "managed by YAML" cards —
 * operators still edit those via their bulwark.yaml.
 *
 * The "Send test" button fires a synthetic event end-to-end. The
 * synthetic flag bypasses each channel's own MinLevel filter so the
 * test always reaches its destination.
 */
export default function Notifiers() {
  const { data, loading, error, refresh } = useNotifiers();
  const { send, busy: testingName, error: sendError } = useTestNotifier();
  const { remove, busy: deletingID, error: deleteError } = useDeleteNotifier();
  const [lastSent, setLastSent] = useState<string | null>(null);
  const [modalOpen, setModalOpen] = useState(false);

  async function onTest(name: string) {
    setLastSent(null);
    try {
      await send(name);
      setLastSent(name);
    } catch {
      // sendError surfaces in the card.
    }
  }

  async function onDelete(id: string, name: string) {
    if (!window.confirm(`Delete notifier "${name}"? Yaml-defined channels are not affected.`)) {
      return;
    }
    try {
      await remove(id);
      void refresh();
    } catch {
      // deleteError shown inline.
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Notifiers</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Configured channels and their thresholds. Add new channels via the
            dashboard — they persist to the encrypted config store and load
            without a restart. Yaml-defined channels stay editable in your
            <code className="mx-1">bulwark.yaml</code>.
          </p>
        </div>
        <Button variant="primary" onClick={() => setModalOpen(true)}>
          Add notifier
        </Button>
      </div>

      {sendError ? (
        <p className="text-sm text-red-600" role="alert">
          {sendError}
        </p>
      ) : null}
      {deleteError ? (
        <p className="text-sm text-red-600" role="alert">
          {deleteError}
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
              No notifiers configured. Click <strong>Add notifier</strong> above
              to wire up Slack, Discord, Teams, SMTP, or Home Assistant — or
              add a <code>notifications.*</code> block to your{" "}
              <code>bulwark.yaml</code> and restart for the legacy path.
            </p>
          </CardBody>
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          {data.map((n) => {
            const key = n.id ?? `yaml:${n.name}`;
            const isYAML = n.source === "yaml";
            return (
              <Card key={key}>
                <CardHeader>
                  <div className="flex items-start justify-between gap-2">
                    <CardTitle>{n.name}</CardTitle>
                    <Badge tone={isYAML ? "info" : "safe"}>
                      {isYAML ? "managed by YAML" : "managed by UI"}
                    </Badge>
                  </div>
                  <CardDescription>
                    Min level <Badge tone="info">{n.min_level}</Badge>
                  </CardDescription>
                </CardHeader>
                <CardBody className="flex items-center justify-between gap-3">
                  <div className="text-xs text-muted-foreground">
                    Test events use the synthetic flag and ignore the channel's
                    level threshold.
                  </div>
                  <div className="flex items-center gap-2">
                    <Button
                      size="sm"
                      variant="primary"
                      onClick={() => onTest(n.name)}
                      disabled={testingName === n.name}
                    >
                      {testingName === n.name ? <Spinner /> : null}
                      Send test
                    </Button>
                    {!isYAML && n.id && (
                      <Button
                        size="sm"
                        variant="destructive"
                        onClick={() => onDelete(n.id!, n.name)}
                        disabled={deletingID === n.id}
                      >
                        {deletingID === n.id ? <Spinner /> : null}
                        Delete
                      </Button>
                    )}
                  </div>
                </CardBody>
              </Card>
            );
          })}
        </div>
      )}

      <div className="text-right">
        <Button size="sm" variant="ghost" onClick={() => void refresh()}>
          Refresh
        </Button>
      </div>

      <AddNotifierModal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        onCreated={() => void refresh()}
      />
    </div>
  );
}
