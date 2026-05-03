import { useMemo, useState } from "react";
import { Badge } from "@/components/ui/Badge";
import { Card, CardBody, CardDescription, CardHeader, CardTitle } from "@/components/ui/Card";
import { TBody, TD, TH, THead, TR, Table } from "@/components/ui/Table";
import { formatTimestamp } from "@/lib/format";
import { useAudit } from "@/lib/hooks";
import { Button } from "@/components/ui/Button";

/**
 * Audit shows the daemon's append-only decision + apply log. The data
 * comes from the same JSONL file `bulwark audit` reads, just over
 * HTTP. Filter chips narrow on the most useful subsets — there's no
 * regex/full-text search yet (deferred until someone asks).
 */
export default function Audit() {
  const { data, loading, error, refresh } = useAudit(200);
  const [actionFilter, setActionFilter] = useState<string | "all">("all");

  const actions = useMemo(() => {
    const set = new Set<string>();
    (data ?? []).forEach((e) => set.add(e.action));
    return Array.from(set).sort();
  }, [data]);

  const rows = useMemo(() => {
    const all = data ?? [];
    if (actionFilter === "all") return all;
    return all.filter((e) => e.action === actionFilter);
  }, [data, actionFilter]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Audit</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Newest first. Every decision, forgotten decision, applied update,
          rollback, and stack-skip lands here. Same data as <code>bulwark audit</code>.
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-2 text-sm">
        <Button
          size="sm"
          variant={actionFilter === "all" ? "primary" : "secondary"}
          onClick={() => setActionFilter("all")}
        >
          All
        </Button>
        {actions.map((a) => (
          <Button
            key={a}
            size="sm"
            variant={actionFilter === a ? "primary" : "secondary"}
            onClick={() => setActionFilter(a)}
          >
            {a}
          </Button>
        ))}
        <span className="ml-auto text-xs text-muted-foreground">
          {rows.length} of {data?.length ?? 0}
        </span>
        <Button size="sm" variant="ghost" onClick={() => void refresh()}>
          Refresh
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Events</CardTitle>
          <CardDescription>Up to 200 most recent.</CardDescription>
        </CardHeader>
        <CardBody>
          {loading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : error ? (
            <p className="text-sm text-red-600">{error}</p>
          ) : rows.length === 0 ? (
            <p className="text-sm text-muted-foreground">No events recorded yet.</p>
          ) : (
            <Table>
              <THead>
                <TR>
                  <TH>Time</TH>
                  <TH>Action</TH>
                  <TH>Actor</TH>
                  <TH>Container</TH>
                  <TH>Detail</TH>
                </TR>
              </THead>
              <TBody>
                {rows.map((e, i) => (
                  <TR key={`${e.time}-${i}`}>
                    <TD className="whitespace-nowrap text-xs text-muted-foreground">
                      {formatTimestamp(e.time)}
                    </TD>
                    <TD>
                      <Badge tone={toneForAction(e.action)}>{e.action}</Badge>
                    </TD>
                    <TD className="text-xs">{e.actor ?? "—"}</TD>
                    <TD className="font-medium">{e.container ?? "—"}</TD>
                    <TD className="text-xs text-muted-foreground">
                      {e.detail || e.note || "—"}
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          )}
        </CardBody>
      </Card>
    </div>
  );
}

function toneForAction(action: string) {
  if (action.startsWith("apply.success")) return "safe";
  if (action.startsWith("apply.rolled_back") || action.startsWith("apply.failed")) {
    return "breaking";
  }
  if (action.startsWith("apply.stack_skipped")) return "stack-skipped";
  if (action.startsWith("decision.")) return "info";
  return "neutral";
}
