import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/Button";
import { Card, CardBody, CardDescription, CardHeader, CardTitle } from "@/components/ui/Card";
import { TBody, TD, TH, THead, TR, Table } from "@/components/ui/Table";
import { formatTimestamp, relativeTime } from "@/lib/format";
import { useSnapshots } from "@/lib/hooks";

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
