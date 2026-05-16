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
  id?: string;
  source: "yaml" | "ui";
  name: string;
  min_level: string;
}

export type NotifierKind =
  | "slack"
  | "discord"
  | "teams"
  | "smtp"
  | "homeassistant";

export interface NotifierEntryDetail {
  id: string;
  name: string;
  kind: NotifierKind;
  min_level: string;
  enabled: boolean;
  slack?: { webhook_url: string; channel?: string };
  discord?: { webhook_url: string };
  teams?: { webhook_url: string };
  smtp?: {
    host: string;
    port: number;
    username?: string;
    password?: string;
    from: string;
    to: string[];
    tls?: boolean;
  };
  homeassistant?: { url: string; token: string };
}

export interface SettingsSection {
  name: string;
  restart_required: boolean;
}

export interface PolicyOverride {
  patch?: string;
  minor?: string;
  major?: string;
  digest?: string;
  latest?: string;
  lsio_rebuild?: string;
  prerelease?: string;
}

export interface ClassificationOverride {
  default_risk?: string;
  policies?: PolicyOverride;
  changelog_max_chars?: number;
}

export interface ScheduleOverride {
  check?: string;
}

export interface SettingsOverride {
  schedule?: ScheduleOverride;
  classification?: ClassificationOverride;
  updated_at?: string;
}

export interface SettingsResponse {
  settings: SettingsOverride;
  sections: SettingsSection[];
}

export interface EffectiveConfigResponse {
  config: unknown;
  overridden_sections: string[];
}

export interface HostInfo {
  platform: string;
  version?: string;
  capabilities: string[];
  suggested_backend?: string;
  configured_backend?: string;
}

export interface ContainerOverride {
  snapshot_auto?: boolean;
  snapshot_dataset?: string;
  updated_at?: string;
}

export type ContainerSnapshotMode = "from-label" | "auto" | "off";

export interface NotifierCreateRequest {
  name: string;
  kind: NotifierKind;
  min_level?: string;
  enabled: boolean;
  slack?: { webhook_url: string; channel?: string };
  discord?: { webhook_url: string };
  teams?: { webhook_url: string };
  smtp?: {
    host: string;
    port: number;
    username?: string;
    password?: string;
    from: string;
    to: string[];
    tls?: boolean;
  };
  homeassistant?: {
    url: string;
    token: string;
  };
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
