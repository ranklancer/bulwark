import { useMemo, useState } from "react";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody, CardDescription, CardHeader, CardTitle } from "@/components/ui/Card";
import { Spinner } from "@/components/ui/Spinner";
import { TBody, TD, TH, THead, TR, Table } from "@/components/ui/Table";
import { riskLabel, riskTone } from "@/lib/format";
import { useDecide, useQueue } from "@/lib/hooks";
import type { QueueRow } from "@/lib/types";

export default function Queue() {
  const queue = useQueue();
  const { decide, submitting } = useDecide();
  const [pendingRow, setPendingRow] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const rows = useMemo(() => queue.data ?? [], [queue.data]);
  const pending = rows.filter((r) => r.decision === "pending");
  const decided = rows.filter((r) => r.decision !== "pending");

  async function onDecide(row: QueueRow, decision: "approved" | "rejected") {
    setError(null);
    setPendingRow(row.container);
    try {
      await decide({ container: row.container, decision });
      await queue.refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setPendingRow(null);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Queue</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          REVIEW-tier updates awaiting your call. Approving silences future
          notifications for the (container, digest) pair and lets the next
          scan auto-apply it. BREAKING updates never auto-apply.
        </p>
      </div>

      {error ? (
        <p className="text-sm text-red-600" role="alert">
          {error}
        </p>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>Pending decisions</CardTitle>
          <CardDescription>{pending.length} waiting</CardDescription>
        </CardHeader>
        <CardBody>
          {queue.loading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : queue.error ? (
            <p className="text-sm text-red-600">{queue.error}</p>
          ) : pending.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              Nothing pending — every REVIEW-tier update has been decided.
            </p>
          ) : (
            <Table>
              <THead>
                <TR>
                  <TH>Container</TH>
                  <TH>Image</TH>
                  <TH>Risk</TH>
                  <TH>Version</TH>
                  <TH className="text-right">Decision</TH>
                </TR>
              </THead>
              <TBody>
                {pending.map((row) => {
                  const busy = submitting && pendingRow === row.container;
                  return (
                    <TR key={`${row.container}-${row.registry_digest ?? ""}`}>
                      <TD className="font-medium">{row.container}</TD>
                      <TD>
                        <code className="rounded bg-muted px-1.5 py-0.5 text-xs">
                          {row.image ?? "—"}
                        </code>
                      </TD>
                      <TD>
                        <Badge tone={riskTone(row.level)}>{riskLabel(row.level)}</Badge>
                      </TD>
                      <TD className="text-xs">
                        {row.from || row.to ? (
                          <code className="rounded bg-muted px-1.5 py-0.5">
                            {row.from ?? "?"} → {row.to ?? "?"}
                          </code>
                        ) : (
                          <span className="text-muted-foreground">—</span>
                        )}
                      </TD>
                      <TD className="text-right">
                        <div className="inline-flex items-center gap-2">
                          <Button
                            size="sm"
                            variant="primary"
                            onClick={() => onDecide(row, "approved")}
                            disabled={busy}
                          >
                            {busy ? <Spinner /> : null}
                            Approve
                          </Button>
                          <Button
                            size="sm"
                            variant="destructive"
                            onClick={() => onDecide(row, "rejected")}
                            disabled={busy}
                          >
                            Reject
                          </Button>
                        </div>
                      </TD>
                    </TR>
                  );
                })}
              </TBody>
            </Table>
          )}
        </CardBody>
      </Card>

      {decided.length > 0 ? (
        <Card>
          <CardHeader>
            <CardTitle>Recent decisions</CardTitle>
            <CardDescription>{decided.length} on file</CardDescription>
          </CardHeader>
          <CardBody>
            <Table>
              <THead>
                <TR>
                  <TH>Container</TH>
                  <TH>Image</TH>
                  <TH>Decision</TH>
                  <TH>Decided by</TH>
                  <TH>Decided at</TH>
                </TR>
              </THead>
              <TBody>
                {decided.map((row) => (
                  <TR key={`${row.container}-${row.registry_digest ?? ""}-${row.decided_at ?? ""}`}>
                    <TD className="font-medium">{row.container}</TD>
                    <TD>
                      <code className="rounded bg-muted px-1.5 py-0.5 text-xs">
                        {row.image ?? "—"}
                      </code>
                    </TD>
                    <TD>
                      <Badge tone={row.decision === "approved" ? "safe" : "breaking"}>
                        {row.decision.toUpperCase()}
                      </Badge>
                    </TD>
                    <TD className="text-xs text-muted-foreground">
                      {row.decided_by ?? "—"}
                    </TD>
                    <TD className="text-xs text-muted-foreground">
                      {row.decided_at ?? "—"}
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          </CardBody>
        </Card>
      ) : null}
    </div>
  );
}
