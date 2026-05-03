import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody, CardDescription, CardHeader, CardTitle } from "@/components/ui/Card";
import { TBody, TD, TH, THead, TR, Table } from "@/components/ui/Table";
import { formatTimestamp, riskLabel, riskTone } from "@/lib/format";
import { useContainers } from "@/lib/hooks";

type Filter = "all" | "pending" | "skipped";

/**
 * Containers is the Docker-host inventory view, derived from the most
 * recent scan record so it reflects exactly what the daemon last saw
 * (no fresh socket call here). Each row deep-links into the scan
 * detail page where the per-container row is already rendered.
 */
export default function Containers() {
  const { data, loading, error, refresh } = useContainers();
  const [filter, setFilter] = useState<Filter>("all");

  const rows = useMemo(() => {
    const all = data ?? [];
    switch (filter) {
      case "pending":
        return all.filter((c) => c.update_available && !c.skipped);
      case "skipped":
        return all.filter((c) => c.skipped);
      default:
        return all;
    }
  }, [data, filter]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Containers</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          The host inventory as of the last scan. Click a row's last-scan
          link for full classification detail.
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-2 text-sm">
        <Button
          size="sm"
          variant={filter === "all" ? "primary" : "secondary"}
          onClick={() => setFilter("all")}
        >
          All
        </Button>
        <Button
          size="sm"
          variant={filter === "pending" ? "primary" : "secondary"}
          onClick={() => setFilter("pending")}
        >
          Has update
        </Button>
        <Button
          size="sm"
          variant={filter === "skipped" ? "primary" : "secondary"}
          onClick={() => setFilter("skipped")}
        >
          Skipped
        </Button>
        <span className="ml-auto text-xs text-muted-foreground">
          {rows.length} of {data?.length ?? 0}
        </span>
        <Button size="sm" variant="ghost" onClick={() => void refresh()}>
          Refresh
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Inventory</CardTitle>
          <CardDescription>
            Source: most-recent scan record.
            {data?.[0]?.last_scan_at ? ` Scan at ${formatTimestamp(data[0].last_scan_at)}.` : ""}
          </CardDescription>
        </CardHeader>
        <CardBody>
          {loading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : error ? (
            <p className="text-sm text-red-600">{error}</p>
          ) : rows.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No containers match the current filter.
            </p>
          ) : (
            <Table>
              <THead>
                <TR>
                  <TH>Container</TH>
                  <TH>Image</TH>
                  <TH>Stack</TH>
                  <TH>Risk</TH>
                  <TH>Status</TH>
                  <TH>Last scan</TH>
                </TR>
              </THead>
              <TBody>
                {rows.map((c) => (
                  <TR key={c.container_name}>
                    <TD className="font-medium">{c.container_name}</TD>
                    <TD>
                      <code className="rounded bg-muted px-1.5 py-0.5 text-xs">
                        {c.image ?? "—"}
                      </code>
                    </TD>
                    <TD className="text-xs text-muted-foreground">
                      {c.compose_project ?? "—"}
                    </TD>
                    <TD>
                      {c.skipped ? (
                        <Badge tone="neutral">SKIPPED</Badge>
                      ) : (
                        <Badge tone={riskTone(c.level)}>{riskLabel(c.level)}</Badge>
                      )}
                    </TD>
                    <TD className="text-xs">
                      {c.skipped ? (
                        <span className="text-muted-foreground">{c.skip_reason ?? "—"}</span>
                      ) : c.update_available ? (
                        <span className="text-amber-700 dark:text-amber-400">
                          {c.from && c.to ? `${c.from} → ${c.to}` : "update available"}
                        </span>
                      ) : (
                        <span className="text-emerald-700 dark:text-emerald-400">up to date</span>
                      )}
                    </TD>
                    <TD className="text-xs">
                      {c.last_scan_id ? (
                        <Link
                          to={`/history/${encodeURIComponent(c.last_scan_id)}`}
                          className="underline underline-offset-4"
                        >
                          details
                        </Link>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
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
