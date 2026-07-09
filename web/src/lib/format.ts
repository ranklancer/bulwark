import type { BadgeTone } from "@/components/ui/Badge";
import type { RiskLevel, SecurityAssessment, SecurityUrgency } from "./types";

export function riskTone(level: RiskLevel | undefined): BadgeTone {
  switch (level) {
    case "safe":
      return "safe";
    case "review":
      return "review";
    case "breaking":
      return "breaking";
    default:
      return "neutral";
  }
}

export function riskLabel(level: RiskLevel | undefined): string {
  switch (level) {
    case "safe":
      return "SAFE";
    case "review":
      return "REVIEW";
    case "breaking":
      return "BREAKING";
    default:
      return "—";
  }
}

const RTF = new Intl.RelativeTimeFormat("en", { numeric: "auto" });

/**
 * Render a duration relative to "now" with sensible units. Matches the
 * legacy dashboard's "2h ago" style without bringing in date-fns.
 */
export function relativeTime(iso: string | undefined, now: Date = new Date()): string {
  if (!iso) return "—";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return "—";
  const seconds = Math.round((t - now.getTime()) / 1000);
  const abs = Math.abs(seconds);
  if (abs < 60) return RTF.format(seconds, "second");
  if (abs < 3600) return RTF.format(Math.round(seconds / 60), "minute");
  if (abs < 86400) return RTF.format(Math.round(seconds / 3600), "hour");
  return RTF.format(Math.round(seconds / 86400), "day");
}

/** "2026-05-03 14:33 UTC" — terse and consistent. */
export function formatTimestamp(iso: string | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  const pad = (n: number) => n.toString().padStart(2, "0");
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} UTC`;
}

export function urgencyTone(u: SecurityUrgency | undefined): BadgeTone {
  switch (u) {
    case "urgent":
      return "urgent";
    case "recommended":
      return "recommended";
    default:
      return "neutral";
  }
}

export function urgencyLabel(u: SecurityUrgency | undefined): string {
  switch (u) {
    case "urgent":
      return "SECURITY: URGENT";
    case "recommended":
      return "SECURITY: RECOMMENDED";
    default:
      return "—";
  }
}

/** Compact "closes 2 CVEs (1 critical, 1 high)" summary. Empty when none. */
export function closedCvesSummary(sec: SecurityAssessment | undefined): string {
  if (!sec || sec.closed_count <= 0) return "";
  const parts: string[] = [];
  if (sec.critical_closed > 0) parts.push(`${sec.critical_closed} critical`);
  if (sec.high_closed > 0) parts.push(`${sec.high_closed} high`);
  const detail = parts.length ? ` (${parts.join(", ")})` : "";
  const n = sec.closed_count;
  return `closes ${n} CVE${n === 1 ? "" : "s"}${detail}`;
}
