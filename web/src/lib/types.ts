// Wire types for Bulwark's JSON API. These mirror the Go-side
// store.ScanRecord / queueRow / etc. — keep field names in sync when
// the Go side changes.

export type RiskLevel = "safe" | "review" | "breaking" | "unknown";

export interface ScanSummary {
  total: number;
  pending: number;
  breaking: number;
  review: number;
  safe: number;
  skipped: number;
  errored: number;
}

export interface ScanResult {
  container_id: string;
  container_name: string;
  image: string;
  compose_project?: string;
  skipped?: boolean;
  skip_reason?: string;
  update_available: boolean;
  local_digest?: string;
  registry_digest?: string;
  level?: RiskLevel;
  kind?: string;
  confidence?: string;
  from?: string;
  to?: string;
  rationale?: string;
  notes_source?: string;
  release_url?: string;
  error?: string;
}

export interface ScanRecord {
  id: string;
  started_at: string;
  finished_at: string;
  host?: string;
  summary: ScanSummary;
  results: ScanResult[];
}

export type Decision = "pending" | "approved" | "rejected";

export interface QueueRow {
  container: string;
  image?: string;
  level?: RiskLevel;
  from?: string;
  to?: string;
  registry_digest?: string;
  decision: Decision;
  decided_by?: string;
  decided_at?: string;
  note?: string;
}

export interface AuditEvent {
  time: string;
  action: string;
  actor?: string;
  container?: string;
  image?: string;
  decision?: string;
  note?: string;
  level?: RiskLevel;
  digest?: string;
  detail?: string;
}

export interface NotifierEntry {
  name: string;
  min_level: string;
}

export interface SnapshotEntry {
  id: string;
  target: string;
  label?: string;
  created_at: string;
}

export interface ContainerEntry {
  container_id?: string;
  container_name: string;
  image?: string;
  compose_project?: string;
  skipped?: boolean;
  skip_reason?: string;
  update_available: boolean;
  level?: RiskLevel;
  from?: string;
  to?: string;
  last_scan_id?: string;
  last_scan_at?: string;
}
