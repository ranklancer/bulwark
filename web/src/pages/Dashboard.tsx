import { useState } from "react";
import { Link } from "react-router-dom";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody, CardDescription, CardHeader, CardTitle } from "@/components/ui/Card";
import { Spinner } from "@/components/ui/Spinner";
import { TBody, TD, TH, THead, TR, Table } from "@/components/ui/Table";
import { EventTypes, useLiveRefresh } from "@/lib/events";
import { formatTimestamp, relativeTime, riskLabel, riskTone } from "@/lib/format";
import { useScansList, useTriggerScan } from "@/lib/hooks";
import type { ScanRecord } from "@/lib/types";

export default function Dashboard() {
  const scans = useScansList(10);
  const { trigger, triggering, error: triggerError } = useTriggerScan();
  const [info, setInfo] = useState<string | null>(null);

  // Live updates: refetch when any of these events arrives so the
  // dashboard reflects new scans + apply outcomes without polling.
  useLiveRefresh(
    [
      EventTypes.ScanCompleted,
      EventTypes.ApplySuccess,
      EventTypes.ApplyFailed,
      EventTypes.ApplyRolledBack,
    ],
    scans.refresh,
  );

  const latest: ScanRecord | undefined = scans.data?.[0];

  async function onScanNow() {
    setInfo(null);
    try {
      await trigger();
      setInfo("Scan queued. Refresh in a moment.");
      // Give the daemon a beat, then re-fetch.
      setTimeout(() => void scans.refresh(), 1500);
    } catch {
      // Error surfaces via triggerError.
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Snapshot of the most recent scan + the last few cycles.
          </p>
        </div>
        <div className="flex flex-col items-end gap-1.5">
          <Button variant="primary" onClick={onScanNow} disabled={triggering}>
            {triggering ? <Spinner /> : null}
            {triggering ? "Triggering…" : "Scan now"}
          </Button>
          {info ? <span className="text-xs text-muted-foreground">{info}</span> : null}
          {triggerError ? <span className="text-xs text-red-600">{triggerError}</span> : null}
        </div>
      </div>

      <SummaryCards latest={latest} loading={scans.loading} />

      <Card>
        <CardHeader>
          <CardTitle>Recent scans</CardTitle>
          <CardDescription>Newest first. Click a row for full results.</CardDescription>
        </CardHeader>
        <CardBody>
          {scans.loading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : scans.error ? (
            <p className="text-sm text-red-600">{scans.error}</p>
          ) : !scans.data?.length ? (
            <p className="text-sm text-muted-foreground">No scans recorded yet.</p>
          ) : (
            <Table>
              <THead>
                <TR>
                  <TH>Started</TH>
                  <TH>Pending</TH>
                  <TH>Breaking</TH>
                  <TH>Review</TH>
                  <TH>Safe</TH>
                  <TH>Total</TH>
                  <TH />
                </TR>
              </THead>
              <TBody>
                {scans.data.map((s) => (
                  <TR key={s.id}>
                    <TD>
                      <Link
                        to={`/history/${encodeURIComponent(s.id)}`}
                        className="font-medium hover:underline"
                      >
                        {relativeTime(s.started_at)}
                      </Link>
                      <div className="text-xs text-muted-foreground">
                        {formatTimestamp(s.started_at)}
                      </div>
                    </TD>
                    <TD>{s.summary.pending}</TD>
                    <TD>{s.summary.breaking}</TD>
                    <TD>{s.summary.review}</TD>
                    <TD>{s.summary.safe}</TD>
                    <TD>{s.summary.total}</TD>
                    <TD>
                      <Link
                        to={`/history/${encodeURIComponent(s.id)}`}
                        className="text-xs underline underline-offset-4"
                      >
                        details
                      </Link>
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

function SummaryCards({ latest, loading }: { latest: ScanRecord | undefined; loading: boolean }) {
  if (loading) {
    return (
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <Card key={i}>
            <CardBody className="text-sm text-muted-foreground">Loading…</CardBody>
          </Card>
        ))}
      </div>
    );
  }
  if (!latest) {
    return (
      <Card>
        <CardBody>
          <p className="text-sm text-muted-foreground">
            No scans recorded yet. Trigger one with the “Scan now” button above.
          </p>
        </CardBody>
      </Card>
    );
  }
  const cards: { label: string; value: number; tone?: "safe" | "review" | "breaking" }[] = [
    { label: "Pending", value: latest.summary.pending },
    { label: "Breaking", value: latest.summary.breaking, tone: "breaking" },
    { label: "Review", value: latest.summary.review, tone: "review" },
    { label: "Safe", value: latest.summary.safe, tone: "safe" },
  ];
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
        <span>Latest scan {relativeTime(latest.started_at)}</span>
        <span>·</span>
        <span>{formatTimestamp(latest.started_at)}</span>
        {latest.host ? (
          <>
            <span>·</span>
            <span>host {latest.host}</span>
          </>
        ) : null}
      </div>
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        {cards.map((c) => (
          <Card key={c.label}>
            <CardBody>
              <div className="text-xs text-muted-foreground">{c.label}</div>
              <div className="mt-1 flex items-center gap-2">
                <span className="text-3xl font-semibold tabular-nums">{c.value}</span>
                {c.tone ? (
                  <Badge tone={riskTone(c.tone)}>{riskLabel(c.tone)}</Badge>
                ) : null}
              </div>
            </CardBody>
          </Card>
        ))}
      </div>
    </div>
  );
}
