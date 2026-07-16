import { useState, type FormEvent } from "react";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody, CardDescription, CardHeader, CardTitle } from "@/components/ui/Card";
import { TBody, TD, TH, THead, TR, Table } from "@/components/ui/Table";
import { formatTimestamp, relativeTime } from "@/lib/format";
import { useHost, useSnapshots } from "@/lib/hooks";
import type { HostInfo } from "@/lib/types";

const PLATFORM_LABEL: Record<string, string> = {
  "truenas-scale": "TrueNAS SCALE",
  "proxmox-ve": "Proxmox VE",
  unraid: "Unraid",
  zfs: "Linux + ZFS",
  btrfs: "Linux + Btrfs",
  unknown: "Unknown",
};

/**
 * Snapshots is the dashboard's read-only view of the snapshot
 * backend's contents for a given target (ZFS dataset / Btrfs
 * subvolume / Restic backup path). Restore + prune intentionally
 * stay CLI-only — both are destructive enough that we want operators
 * to type the explicit `bulwark snapshot restore --yes <id>` form.
 */
export default function Snapshots() {
  const [target, setTarget] = useState("");
  const [submitted, setSubmitted] = useState("");
  const { data, loading, error, refresh } = useSnapshots(submitted);
  const { data: host, loading: hostLoading } = useHost();

  function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setSubmitted(target.trim());
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Snapshots</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Pre-update snapshots taken by the daemon's configured backend.
          Read-only here — to roll back or prune, run
          <code className="mx-1 rounded bg-muted px-1.5 py-0.5">bulwark snapshot restore --yes &lt;id&gt;</code>
          on the host.
        </p>
      </div>

      {hostLoading ? null : host ? <HostPanel host={host} /> : null}

      <Card>
        <CardHeader>
          <CardTitle>Target</CardTitle>
          <CardDescription>
            Enter the dataset / subvolume / path the backend tracks for one of
            your containers. Matches the
            <code className="mx-1 rounded bg-muted px-1.5 py-0.5">bulwark.snapshot.dataset</code>
            container label.
          </CardDescription>
        </CardHeader>
        <CardBody>
          <form onSubmit={onSubmit} className="flex flex-wrap items-center gap-2">
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="tank/docker/sonarr or /var/lib/sonarr"
              className="min-w-[18rem] flex-1 rounded-md border border-border bg-background px-3 py-2 text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary"
            />
            <Button type="submit" variant="primary" size="md" disabled={!target.trim()}>
              List
            </Button>
            <Button
              type="button"
              variant="ghost"
              size="md"
              onClick={() => void refresh()}
              disabled={!submitted}
            >
              Refresh
            </Button>
          </form>
        </CardBody>
      </Card>

      {submitted ? (
        <Card>
          <CardHeader>
            <CardTitle>{submitted}</CardTitle>
            <CardDescription>
              {data?.length ?? 0} snapshot{(data?.length ?? 0) === 1 ? "" : "s"}
            </CardDescription>
          </CardHeader>
          <CardBody>
            {loading ? (
              <p className="text-sm text-muted-foreground">Loading…</p>
            ) : error ? (
              <p className="text-sm text-red-600">{error}</p>
            ) : !data?.length ? (
              <p className="text-sm text-muted-foreground">
                No snapshots recorded for this target yet.
              </p>
            ) : (
              <Table>
                <THead>
                  <TR>
                    <TH>ID</TH>
                    <TH>Label</TH>
                    <TH>Created</TH>
                  </TR>
                </THead>
                <TBody>
                  {data.map((s) => (
                    <TR key={s.id}>
                      <TD>
                        <code className="rounded bg-muted px-1.5 py-0.5 text-xs">
                          {s.id}
                        </code>
                      </TD>
                      <TD className="text-xs text-muted-foreground">
                        {s.label || "—"}
                      </TD>
                      <TD>
                        <div>{relativeTime(s.created_at)}</div>
                        <div className="text-xs text-muted-foreground">
                          {formatTimestamp(s.created_at)}
                        </div>
                      </TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
            )}
          </CardBody>
        </Card>
      ) : null}
    </div>
  );
}

function HostPanel({ host }: { host: HostInfo }) {
  const label = PLATFORM_LABEL[host.platform] ?? host.platform;
  const mismatch =
    host.configured_backend &&
    host.suggested_backend &&
    host.configured_backend !== host.suggested_backend;

  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between gap-2">
          <div>
            <CardTitle>Detected host</CardTitle>
            <CardDescription>
              Automatic detection runs once at daemon start. Restart Bulwark
              after moving the daemon to a different host class.
            </CardDescription>
          </div>
          <Badge tone="info">{label}</Badge>
        </div>
      </CardHeader>
      <CardBody>
        <dl className="grid grid-cols-1 gap-x-6 gap-y-2 text-sm md:grid-cols-2">
          <Row label="Platform">{label}</Row>
          {host.version ? <Row label="Version">{host.version}</Row> : null}
          <Row label="Capabilities">
            {host.capabilities.length === 0 ? (
              <span className="text-muted-foreground">none</span>
            ) : (
              <span className="inline-flex flex-wrap gap-1">
                {host.capabilities.map((c) => (
                  <Badge key={c} tone="safe">
                    {c}
                  </Badge>
                ))}
              </span>
            )}
          </Row>
          <Row label="Configured backend">
            {host.configured_backend ? (
              <code className="rounded bg-muted px-1.5 py-0.5 text-xs">
                {host.configured_backend}
              </code>
            ) : (
              <span className="text-muted-foreground">none</span>
            )}
          </Row>
          <Row label="Suggested backend">
            {host.suggested_backend ? (
              <code className="rounded bg-muted px-1.5 py-0.5 text-xs">
                {host.suggested_backend}
              </code>
            ) : (
              <span className="text-muted-foreground">none</span>
            )}
          </Row>
        </dl>
        {mismatch ? (
          <div className="mt-3 rounded-md border border-yellow-400 bg-yellow-50 px-3 py-2 text-xs text-yellow-900 dark:border-yellow-700 dark:bg-yellow-950 dark:text-yellow-200">
            <strong>Backend mismatch.</strong> Configured{" "}
            <code>{host.configured_backend}</code>, but the host appears to
            be best served by <code>{host.suggested_backend}</code>. Update
            <code className="mx-1">snapshots.backend</code> in
            <code className="mx-1">bulwark.yaml</code> if the suggestion fits.
          </div>
        ) : null}
        <p className="mt-3 text-xs text-muted-foreground">
          Set <code>bulwark.snapshot.auto: "true"</code> on a container's labels
          to have Bulwark walk the container's bind mounts and infer the
          snapshot target automatically. Explicit{" "}
          <code>bulwark.snapshot.dataset</code> always wins.
        </p>
      </CardBody>
    </Card>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <>
      <dt className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
        {label}
      </dt>
      <dd>{children}</dd>
    </>
  );
}
