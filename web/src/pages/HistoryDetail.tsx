import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Badge } from "@/components/ui/Badge";
import { Card, CardBody, CardDescription, CardHeader, CardTitle } from "@/components/ui/Card";
import { TBody, TD, TH, THead, TR, Table } from "@/components/ui/Table";
import { formatTimestamp, riskLabel, riskTone } from "@/lib/format";
import { useScan } from "@/lib/hooks";
import type { ScanResult } from "@/lib/types";

export default function HistoryDetail() {
  const { id } = useParams<{ id: string }>();
  const { data: scan, loading, error } = useScan(id);
  const [expanded, setExpanded] = useState<string | null>(null);

  if (loading) {
    return <p className="text-sm text-muted-foreground">Loading scan…</p>;
  }
  if (error) {
    return <p className="text-sm text-red-600">{error}</p>;
  }
  if (!scan) {
    return <p className="text-sm text-muted-foreground">Scan not found.</p>;
  }

  return (
    <div className="space-y-6">
      <div>
        <Link
          to="/history"
          className="text-sm text-muted-foreground underline underline-offset-4 hover:text-foreground"
        >
          ← History
        </Link>
        <h1 className="mt-2 text-2xl font-semibold tracking-tight">
          Scan {scan.id}
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          {formatTimestamp(scan.started_at)} → {formatTimestamp(scan.finished_at)}
          {scan.host ? ` · host ${scan.host}` : ""}
        </p>
      </div>

      <SummaryStrip scan={scan} />

      <Card>
        <CardHeader>
          <CardTitle>Per-container results</CardTitle>
          <CardDescription>
            Click a row to expand digest details + rationale.
          </CardDescription>
        </CardHeader>
        <CardBody>
          <Table>
            <THead>
              <TR>
                <TH>Container</TH>
                <TH>Image</TH>
                <TH>Risk</TH>
                <TH>Version</TH>
                <TH>Status</TH>
              </TR>
            </THead>
            <TBody>
              {scan.results.map((r) => {
                const key = `${r.container_name}-${r.registry_digest ?? r.local_digest ?? ""}`;
                const open = expanded === key;
                return (
                  <ResultRow
                    key={key}
                    result={r}
                    open={open}
                    onToggle={() => setExpanded(open ? null : key)}
                  />
                );
              })}
            </TBody>
          </Table>
        </CardBody>
      </Card>
    </div>
  );
}

function SummaryStrip({ scan }: { scan: { summary: { total: number; pending: number; breaking: number; review: number; safe: number; skipped: number; errored: number } } }) {
  const cells: { label: string; value: number }[] = [
    { label: "Total", value: scan.summary.total },
    { label: "Pending", value: scan.summary.pending },
    { label: "Breaking", value: scan.summary.breaking },
    { label: "Review", value: scan.summary.review },
    { label: "Safe", value: scan.summary.safe },
    { label: "Skipped", value: scan.summary.skipped },
    { label: "Errored", value: scan.summary.errored },
  ];
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-7">
      {cells.map((c) => (
        <Card key={c.label}>
          <CardBody>
            <div className="text-xs text-muted-foreground">{c.label}</div>
            <div className="mt-1 text-2xl font-semibold tabular-nums">{c.value}</div>
          </CardBody>
        </Card>
      ))}
    </div>
  );
}

function ResultRow({
  result,
  open,
  onToggle,
}: {
  result: ScanResult;
  open: boolean;
  onToggle: () => void;
}) {
  return (
    <>
      <TR
        className="cursor-pointer transition hover:bg-muted/50"
        onClick={onToggle}
      >
        <TD className="font-medium">
          {result.container_name}
          {result.compose_project ? (
            <div className="text-xs text-muted-foreground">
              stack: {result.compose_project}
            </div>
          ) : null}
        </TD>
        <TD>
          <code className="rounded bg-muted px-1.5 py-0.5 text-xs">{result.image}</code>
        </TD>
        <TD>
          {result.skipped ? (
            <Badge tone="neutral">SKIPPED</Badge>
          ) : (
            <Badge tone={riskTone(result.level)}>{riskLabel(result.level)}</Badge>
          )}
        </TD>
        <TD className="text-xs">
          {result.from || result.to ? (
            <code className="rounded bg-muted px-1.5 py-0.5">
              {result.from ?? "?"} → {result.to ?? "?"}
            </code>
          ) : (
            <span className="text-muted-foreground">—</span>
          )}
        </TD>
        <TD className="text-xs">
          {result.error ? (
            <span className="text-red-600">{result.error}</span>
          ) : result.update_available ? (
            <span className="text-amber-700 dark:text-amber-400">update available</span>
          ) : result.skipped ? (
            <span className="text-muted-foreground">{result.skip_reason ?? "skipped"}</span>
          ) : (
            <span className="text-emerald-700 dark:text-emerald-400">up to date</span>
          )}
        </TD>
      </TR>
      {open ? (
        <TR>
          <TD colSpan={5} className="bg-muted/30">
            <ResultDetails result={result} />
          </TD>
        </TR>
      ) : null}
    </>
  );
}

function ResultDetails({ result }: { result: ScanResult }) {
  return (
    <dl className="grid grid-cols-1 gap-x-6 gap-y-1 px-2 py-3 text-xs sm:grid-cols-[140px_1fr]">
      <DetailRow label="Container ID" value={result.container_id} mono />
      <DetailRow label="Local digest" value={result.local_digest} mono />
      <DetailRow label="Registry digest" value={result.registry_digest} mono />
      <DetailRow label="Kind" value={result.kind} />
      <DetailRow label="Confidence" value={result.confidence} />
      <DetailRow label="Notes source" value={result.notes_source} />
      <DetailRow label="Rationale" value={result.rationale} />
      {result.release_url ? (
        <>
          <dt className="text-muted-foreground">Release notes</dt>
          <dd>
            <a
              href={result.release_url}
              className="underline underline-offset-4"
              target="_blank"
              rel="noreferrer noopener"
            >
              {result.release_url}
            </a>
          </dd>
        </>
      ) : null}
    </dl>
  );
}

function DetailRow({ label, value, mono = false }: { label: string; value?: string; mono?: boolean }) {
  if (!value) return null;
  return (
    <>
      <dt className="text-muted-foreground">{label}</dt>
      <dd className={mono ? "font-mono break-all" : ""}>{value}</dd>
    </>
  );
}
