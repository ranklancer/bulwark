import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/Button";
import { Card, CardBody, CardDescription, CardHeader, CardTitle } from "@/components/ui/Card";
import { TBody, TD, TH, THead, TR, Table } from "@/components/ui/Table";
import { formatTimestamp, relativeTime } from "@/lib/format";
import { useScansList } from "@/lib/hooks";

type Filter = "all" | "with-pending" | "with-breaking";

export default function History() {
  const [limit, setLimit] = useState(50);
  const scans = useScansList(limit);
  const [filter, setFilter] = useState<Filter>("all");

  const rows = useMemo(() => {
    const all = scans.data ?? [];
    switch (filter) {
      case "with-pending":
        return all.filter((s) => s.summary.pending > 0);
      case "with-breaking":
        return all.filter((s) => s.summary.breaking > 0);
      default:
        return all;
    }
  }, [scans.data, filter]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">History</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Every scan the daemon recorded. Pick a row for full per-container
          results.
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-2 text-sm">
        <FilterButton label="All" active={filter === "all"} onClick={() => setFilter("all")} />
        <FilterButton
          label="Has pending"
          active={filter === "with-pending"}
          onClick={() => setFilter("with-pending")}
        />
        <FilterButton
          label="Has breaking"
          active={filter === "with-breaking"}
          onClick={() => setFilter("with-breaking")}
        />
        <span className="ml-auto text-xs text-muted-foreground">
          showing {rows.length} of {scans.data?.length ?? 0}
        </span>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Scans</CardTitle>
          <CardDescription>Newest first.</CardDescription>
        </CardHeader>
        <CardBody>
          {scans.loading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : scans.error ? (
            <p className="text-sm text-red-600">{scans.error}</p>
          ) : rows.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No scans match the current filter.
            </p>
          ) : (
            <Table>
              <THead>
                <TR>
                  <TH>When</TH>
                  <TH>Pending</TH>
                  <TH>Breaking</TH>
                  <TH>Review</TH>
                  <TH>Safe</TH>
                  <TH>Errored</TH>
                  <TH>Total</TH>
                  <TH />
                </TR>
              </THead>
              <TBody>
                {rows.map((s) => (
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
                    <TD>{s.summary.errored}</TD>
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

      <div className="flex justify-center">
        <Button
          variant="secondary"
          size="sm"
          onClick={() => setLimit((l) => l + 50)}
          disabled={scans.loading || Boolean(scans.data && scans.data.length < limit)}
        >
          Load 50 more
        </Button>
      </div>
    </div>
  );
}

function FilterButton({
  label,
  active,
  onClick,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <Button
      size="sm"
      variant={active ? "primary" : "secondary"}
      onClick={onClick}
    >
      {label}
    </Button>
  );
}
