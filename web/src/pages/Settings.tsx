import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardBody, CardDescription, CardHeader, CardTitle } from "@/components/ui/Card";
import { Spinner } from "@/components/ui/Spinner";
import { useEffectiveConfig, usePatchSettings, useSettings } from "@/lib/hooks";
import type {
  ClassificationOverride,
  HealthOverride,
  LoggingOverride,
  ScheduleOverride,
  SnapshotsOverride,
} from "@/lib/types";

type Tab = "classification" | "schedule" | "health" | "logging" | "snapshots" | "advanced";

const RISK_LEVELS = ["safe", "review", "breaking"] as const;

/**
 * Settings is the UI-driven config editor. Editable sections persist
 * to the encrypted config store and merge on top of the yaml-loaded
 * base at use-time. Sections not exposed here stay yaml-only by
 * design (the merged result is visible read-only under "Advanced YAML").
 *
 * Hot-reload semantics per section:
 *   - classification: takes effect on the next scan cycle.
 *   - schedule: requires a daemon restart (cron scheduler is built
 *     once at startup). The UI shows a banner.
 */
export default function Settings() {
  const { data: settings, loading: loadingSettings, error: settingsError, refresh: refreshSettings } = useSettings();
  const { data: effective, loading: loadingEffective, error: effectiveError, refresh: refreshEffective } = useEffectiveConfig();
  const [tab, setTab] = useState<Tab>("classification");

  const overridden = new Set(effective?.overridden_sections ?? []);

  if (settingsError && !loadingSettings) {
    return <p className="text-sm text-red-600">{settingsError}</p>;
  }

  function SectionTab({ id, label }: { id: Tab; label: string }) {
    const isOverridden = overridden.has(id);
    const isActive = tab === id;
    return (
      <button
        type="button"
        onClick={() => setTab(id)}
        className={
          "px-3 py-1.5 text-sm rounded-md transition-colors " +
          (isActive ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:bg-muted")
        }
      >
        {label}
        {isOverridden ? (
          <span className="ml-2 inline-block">
            <Badge tone="info">modified</Badge>
          </span>
        ) : null}
      </button>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Settings</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Daemon-wide configuration. Changes write to the encrypted config
          store; the original <code>bulwark.yaml</code> is left untouched and
          continues to provide bootstrap defaults.
        </p>
      </div>

      <div className="flex flex-wrap gap-2 border-b border-border pb-2">
        <SectionTab id="classification" label="Classification" />
        <SectionTab id="schedule" label="Schedule" />
        <SectionTab id="health" label="Health" />
        <SectionTab id="logging" label="Logging" />
        <SectionTab id="snapshots" label="Snapshots" />
        <SectionTab id="advanced" label="Advanced YAML" />
      </div>

      {loadingSettings && <p className="text-sm text-muted-foreground">Loading…</p>}

      {tab === "classification" && settings && (
        <ClassificationTab
          override={settings.settings.classification ?? {}}
          onSaved={() => {
            void refreshSettings();
            void refreshEffective();
          }}
        />
      )}
      {tab === "schedule" && settings && (
        <ScheduleTab
          override={settings.settings.schedule ?? {}}
          restartRequired={settings.sections.find((s) => s.name === "schedule")?.restart_required ?? true}
          onSaved={() => {
            void refreshSettings();
            void refreshEffective();
          }}
        />
      )}
      {tab === "health" && settings && (
        <HealthTab
          override={settings.settings.health ?? {}}
          restartRequired={settings.sections.find((s) => s.name === "health")?.restart_required ?? false}
          onSaved={() => {
            void refreshSettings();
            void refreshEffective();
          }}
        />
      )}
      {tab === "logging" && settings && (
        <LoggingTab
          override={settings.settings.logging ?? {}}
          restartRequired={settings.sections.find((s) => s.name === "logging")?.restart_required ?? true}
          onSaved={() => {
            void refreshSettings();
            void refreshEffective();
          }}
        />
      )}
      {tab === "snapshots" && settings && (
        <SnapshotsTab
          override={settings.settings.snapshots ?? {}}
          restartRequired={settings.sections.find((s) => s.name === "snapshots")?.restart_required ?? true}
          onSaved={() => {
            void refreshSettings();
            void refreshEffective();
          }}
        />
      )}
      {tab === "advanced" && (
        <AdvancedYAMLTab loading={loadingEffective} error={effectiveError} data={effective?.config} />
      )}

      <div className="flex items-center justify-between gap-4">
        <p className="text-xs text-muted-foreground">
          Notifier configuration lives on its own page:&nbsp;
          <Link to="/notifiers" className="text-primary underline">
            /notifiers
          </Link>
          .
        </p>
        <Button size="sm" variant="ghost" onClick={() => void refreshSettings()}>
          Refresh
        </Button>
      </div>
    </div>
  );
}

function ClassificationTab({
  override,
  onSaved,
}: {
  override: ClassificationOverride;
  onSaved: () => void;
}) {
  const { patch, busy, error } = usePatchSettings();
  const [form, setForm] = useState({
    defaultRisk: override.default_risk ?? "",
    changelog: override.changelog_max_chars?.toString() ?? "",
    policies: {
      patch: override.policies?.patch ?? "",
      minor: override.policies?.minor ?? "",
      major: override.policies?.major ?? "",
      digest: override.policies?.digest ?? "",
      latest: override.policies?.latest ?? "",
      lsio_rebuild: override.policies?.lsio_rebuild ?? "",
      prerelease: override.policies?.prerelease ?? "",
    },
  });

  useEffect(() => {
    setForm({
      defaultRisk: override.default_risk ?? "",
      changelog: override.changelog_max_chars?.toString() ?? "",
      policies: {
        patch: override.policies?.patch ?? "",
        minor: override.policies?.minor ?? "",
        major: override.policies?.major ?? "",
        digest: override.policies?.digest ?? "",
        latest: override.policies?.latest ?? "",
        lsio_rebuild: override.policies?.lsio_rebuild ?? "",
        prerelease: override.policies?.prerelease ?? "",
      },
    });
  }, [override]);

  async function save() {
    const body: ClassificationOverride = {};
    if (form.defaultRisk) body.default_risk = form.defaultRisk;
    if (form.changelog) {
      const n = parseInt(form.changelog, 10);
      if (!isNaN(n)) body.changelog_max_chars = n;
    }
    const p: ClassificationOverride["policies"] = {};
    for (const k of Object.keys(form.policies) as (keyof typeof form.policies)[]) {
      const v = form.policies[k];
      if (v) (p as Record<string, string>)[k] = v;
    }
    if (Object.keys(p).length > 0) body.policies = p;
    if (Object.keys(body).length === 0) return;
    try {
      await patch("classification", body);
      onSaved();
    } catch {
      /* error renders inline */
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Classification policy</CardTitle>
        <CardDescription>
          How Bulwark scores updates. Changes apply at the next scan
          cycle — no daemon restart required.
        </CardDescription>
      </CardHeader>
      <CardBody className="space-y-4">
        <Field label="Default risk (when no other rule fires)">
          <RiskSelect
            value={form.defaultRisk}
            allowEmpty
            onChange={(v) => setForm({ ...form, defaultRisk: v })}
          />
        </Field>
        <Field label="Changelog max chars (truncate release notes)">
          <input
            type="number"
            value={form.changelog}
            onChange={(e) => setForm({ ...form, changelog: e.target.value })}
            className={INPUT}
            placeholder="500"
          />
        </Field>
        <div>
          <p className="mb-2 text-xs font-medium text-muted-foreground">Per-update-type policy</p>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            {(
              [
                ["patch", "Patch (X.Y.Z bump)"],
                ["minor", "Minor (X.Y bump)"],
                ["major", "Major (X bump)"],
                ["digest", "Digest pin update"],
                ["latest", ":latest tag refresh"],
                ["lsio_rebuild", "LinuxServer.io rebuild"],
                ["prerelease", "Prerelease tag"],
              ] as const
            ).map(([key, label]) => (
              <Field key={key} label={label}>
                <RiskSelect
                  value={form.policies[key]}
                  allowEmpty
                  onChange={(v) =>
                    setForm({
                      ...form,
                      policies: { ...form.policies, [key]: v },
                    })
                  }
                />
              </Field>
            ))}
          </div>
        </div>

        {error && (
          <p className="text-sm text-red-600" role="alert">
            {error}
          </p>
        )}

        <div className="flex items-center justify-end gap-2">
          <Button variant="primary" onClick={() => void save()} disabled={busy}>
            {busy ? <Spinner /> : null}
            Save classification overrides
          </Button>
        </div>
      </CardBody>
    </Card>
  );
}

function ScheduleTab({
  override,
  restartRequired,
  onSaved,
}: {
  override: ScheduleOverride;
  restartRequired: boolean;
  onSaved: () => void;
}) {
  const { patch, busy, error } = usePatchSettings();
  const [check, setCheck] = useState(override.check ?? "");

  useEffect(() => {
    setCheck(override.check ?? "");
  }, [override]);

  async function save() {
    try {
      await patch("schedule", { check });
      onSaved();
    } catch {
      /* error renders inline */
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Schedule</CardTitle>
        <CardDescription>Cron expression that drives periodic scans.</CardDescription>
      </CardHeader>
      <CardBody className="space-y-4">
        {restartRequired && (
          <div className="rounded-md border border-yellow-400 bg-yellow-50 px-3 py-2 text-xs text-yellow-900 dark:border-yellow-700 dark:bg-yellow-950 dark:text-yellow-200">
            <strong>Restart required.</strong> Schedule changes persist
            immediately, but the running cron scheduler keeps the old
            schedule until the daemon is restarted.
          </div>
        )}
        <Field label="Scan cron expression">
          <input
            type="text"
            value={check}
            onChange={(e) => setCheck(e.target.value)}
            className={INPUT}
            placeholder="0 */6 * * *"
          />
          <p className="mt-1 text-xs text-muted-foreground">
            Standard 5-field cron. Empty disables the cron path; the daemon
            falls back to its <code>--scan-interval</code> fixed period.
          </p>
        </Field>
        {error && (
          <p className="text-sm text-red-600" role="alert">
            {error}
          </p>
        )}
        <div className="flex items-center justify-end gap-2">
          <Button variant="primary" onClick={() => void save()} disabled={busy}>
            {busy ? <Spinner /> : null}
            Save schedule override
          </Button>
        </div>
      </CardBody>
    </Card>
  );
}

function AdvancedYAMLTab({
  loading,
  error,
  data,
}: {
  loading: boolean;
  error: string | null;
  data: unknown;
}) {
  const rendered = useMemo(() => (data ? yamlStringify(data) : ""), [data]);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Effective configuration (read-only)</CardTitle>
        <CardDescription>
          The merged result of <code>bulwark.yaml</code> + UI overrides. Secrets are
          replaced with <code>"***"</code>. Edit fields not exposed in the
          per-section forms by modifying <code>bulwark.yaml</code> directly and
          restarting the daemon.
        </CardDescription>
      </CardHeader>
      <CardBody>
        {loading ? (
          <p className="text-sm text-muted-foreground">Loading…</p>
        ) : error ? (
          <p className="text-sm text-red-600">{error}</p>
        ) : (
          <pre className="max-h-[60vh] overflow-auto rounded-md border border-border bg-muted/30 p-3 text-xs">
            {rendered}
          </pre>
        )}
      </CardBody>
    </Card>
  );
}

function RiskSelect({
  value,
  onChange,
  allowEmpty,
}: {
  value: string;
  onChange: (v: string) => void;
  allowEmpty?: boolean;
}) {
  return (
    <select value={value} onChange={(e) => onChange(e.target.value)} className={INPUT}>
      {allowEmpty && <option value="">(use yaml default)</option>}
      {RISK_LEVELS.map((r) => (
        <option key={r} value={r}>
          {r}
        </option>
      ))}
    </select>
  );
}

const INPUT =
  "w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary";

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1 block text-xs font-medium text-muted-foreground">{label}</span>
      {children}
    </label>
  );
}

function yamlStringify(v: unknown, indent = 0): string {
  const pad = "  ".repeat(indent);
  if (v === null || v === undefined) return "null";
  if (typeof v === "string") return /[:#\n]/.test(v) || v === "" ? JSON.stringify(v) : v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  if (Array.isArray(v)) {
    if (v.length === 0) return "[]";
    return v
      .map((item) => {
        const child = yamlStringify(item, indent + 1);
        if (child.includes("\n")) return `${pad}-\n${child}`;
        return `${pad}- ${child}`;
      })
      .join("\n");
  }
  if (typeof v === "object") {
    const entries = Object.entries(v as Record<string, unknown>);
    if (entries.length === 0) return "{}";
    return entries
      .map(([k, val]) => {
        if (val !== null && typeof val === "object" && !Array.isArray(val) && Object.keys(val).length > 0) {
          return `${pad}${k}:\n${yamlStringify(val, indent + 1)}`;
        }
        if (Array.isArray(val) && val.length > 0) {
          return `${pad}${k}:\n${yamlStringify(val, indent + 1)}`;
        }
        return `${pad}${k}: ${yamlStringify(val, indent + 1)}`;
      })
      .join("\n");
  }
  return String(v);
}

function RestartBanner({ section }: { section: string }) {
  return (
    <div className="rounded-md border border-yellow-400 bg-yellow-50 px-3 py-2 text-xs text-yellow-900 dark:border-yellow-700 dark:bg-yellow-950 dark:text-yellow-200">
      <strong>Restart required.</strong> {section} changes persist immediately,
      but the daemon picks them up only on its next start. Restart the Bulwark
      container after saving.
    </div>
  );
}

function HealthTab({
  override,
  restartRequired,
  onSaved,
}: {
  override: HealthOverride;
  restartRequired: boolean;
  onSaved: () => void;
}) {
  const { patch, busy, error } = usePatchSettings();
  const [form, setForm] = useState({
    timeout: override.timeout ?? "",
    interval: override.interval ?? "",
    threshold: override.threshold?.toString() ?? "",
    grace: override.grace_period ?? "",
  });
  useEffect(() => {
    setForm({
      timeout: override.timeout ?? "",
      interval: override.interval ?? "",
      threshold: override.threshold?.toString() ?? "",
      grace: override.grace_period ?? "",
    });
  }, [override]);

  async function save() {
    const body: HealthOverride = {};
    if (form.timeout) body.timeout = form.timeout;
    if (form.interval) body.interval = form.interval;
    if (form.threshold) {
      const n = parseInt(form.threshold, 10);
      if (!isNaN(n)) body.threshold = n;
    }
    if (form.grace) body.grace_period = form.grace;
    if (Object.keys(body).length === 0) return;
    try {
      await patch("health", body);
      onSaved();
    } catch {
      /* inline */
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Post-update health check</CardTitle>
        <CardDescription>
          How long Bulwark waits for a recreated container to report healthy
          before rolling back. Takes effect on the next apply cycle.
        </CardDescription>
      </CardHeader>
      <CardBody className="space-y-4">
        {restartRequired && <RestartBanner section="Health" />}
        <Field label="Timeout (Go duration, e.g. 180s)">
          <input
            type="text"
            value={form.timeout}
            onChange={(e) => setForm({ ...form, timeout: e.target.value })}
            className={INPUT}
            placeholder="120s"
          />
        </Field>
        <Field label="Poll interval">
          <input
            type="text"
            value={form.interval}
            onChange={(e) => setForm({ ...form, interval: e.target.value })}
            className={INPUT}
            placeholder="5s"
          />
        </Field>
        <Field label="Healthy threshold (consecutive polls)">
          <input
            type="number"
            min={1}
            value={form.threshold}
            onChange={(e) => setForm({ ...form, threshold: e.target.value })}
            className={INPUT}
            placeholder="3"
          />
        </Field>
        <Field label="Grace period (ignore early-unhealthy noise)">
          <input
            type="text"
            value={form.grace}
            onChange={(e) => setForm({ ...form, grace: e.target.value })}
            className={INPUT}
            placeholder="10s"
          />
        </Field>
        {error && (
          <p className="text-sm text-red-600" role="alert">
            {error}
          </p>
        )}
        <div className="flex items-center justify-end">
          <Button variant="primary" onClick={() => void save()} disabled={busy}>
            {busy ? <Spinner /> : null}
            Save health overrides
          </Button>
        </div>
      </CardBody>
    </Card>
  );
}

function LoggingTab({
  override,
  restartRequired,
  onSaved,
}: {
  override: LoggingOverride;
  restartRequired: boolean;
  onSaved: () => void;
}) {
  const { patch, busy, error } = usePatchSettings();
  const [form, setForm] = useState({
    level: override.level ?? "",
    format: override.format ?? "",
  });
  useEffect(() => {
    setForm({ level: override.level ?? "", format: override.format ?? "" });
  }, [override]);

  async function save() {
    const body: LoggingOverride = {};
    if (form.level) body.level = form.level;
    if (form.format) body.format = form.format;
    if (Object.keys(body).length === 0) return;
    try {
      await patch("logging", body);
      onSaved();
    } catch {
      /* inline */
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Logging</CardTitle>
        <CardDescription>
          Daemon log level + output format. The slog handler is built once at
          startup, so changes here require a daemon restart to take effect.
        </CardDescription>
      </CardHeader>
      <CardBody className="space-y-4">
        {restartRequired && <RestartBanner section="Logging" />}
        <Field label="Level">
          <select
            value={form.level}
            onChange={(e) => setForm({ ...form, level: e.target.value })}
            className={INPUT}
          >
            <option value="">(use yaml default)</option>
            <option value="debug">debug</option>
            <option value="info">info</option>
            <option value="warn">warn</option>
            <option value="error">error</option>
          </select>
        </Field>
        <Field label="Format">
          <select
            value={form.format}
            onChange={(e) => setForm({ ...form, format: e.target.value })}
            className={INPUT}
          >
            <option value="">(use yaml default)</option>
            <option value="text">text</option>
            <option value="json">json</option>
          </select>
        </Field>
        {error && (
          <p className="text-sm text-red-600" role="alert">
            {error}
          </p>
        )}
        <div className="flex items-center justify-end">
          <Button variant="primary" onClick={() => void save()} disabled={busy}>
            {busy ? <Spinner /> : null}
            Save logging overrides
          </Button>
        </div>
      </CardBody>
    </Card>
  );
}

function SnapshotsTab({
  override,
  restartRequired,
  onSaved,
}: {
  override: SnapshotsOverride;
  restartRequired: boolean;
  onSaved: () => void;
}) {
  const { patch, busy, error } = usePatchSettings();
  const [form, setForm] = useState({
    backend: override.backend ?? "",
    url: override.proxmox?.url ?? "",
    token: override.proxmox?.token ?? "",
    node: override.proxmox?.node ?? "",
    vmid: override.proxmox?.vmid?.toString() ?? "",
    kind: override.proxmox?.kind ?? "lxc",
    insecureTLS: override.proxmox?.insecure_tls ?? false,
  });
  useEffect(() => {
    setForm({
      backend: override.backend ?? "",
      url: override.proxmox?.url ?? "",
      token: override.proxmox?.token ?? "",
      node: override.proxmox?.node ?? "",
      vmid: override.proxmox?.vmid?.toString() ?? "",
      kind: override.proxmox?.kind ?? "lxc",
      insecureTLS: override.proxmox?.insecure_tls ?? false,
    });
  }, [override]);

  async function save() {
    const body: SnapshotsOverride = {};
    if (form.backend) body.backend = form.backend;
    if (form.backend === "proxmox" || form.url || form.token || form.node || form.vmid) {
      body.proxmox = {
        url: form.url || undefined,
        // Always send token, even when "***" — the backend
        // recognises the marker and leaves the persisted value
        // untouched. Empty string is an explicit clear.
        token: form.token,
        node: form.node || undefined,
        vmid: form.vmid ? parseInt(form.vmid, 10) : undefined,
        kind: form.kind || undefined,
        insecure_tls: form.insecureTLS,
      };
    }
    try {
      await patch("snapshots", body);
      onSaved();
    } catch {
      /* inline */
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Snapshots</CardTitle>
        <CardDescription>
          Snapshot backend selection + Proxmox VE credentials. The Proxmox API
          token is stored encrypted in the daemon's config store; the
          dashboard never displays the raw value once saved.
        </CardDescription>
      </CardHeader>
      <CardBody className="space-y-4">
        {restartRequired && <RestartBanner section="Snapshots" />}
        <Field label="Backend">
          <select
            value={form.backend}
            onChange={(e) => setForm({ ...form, backend: e.target.value })}
            className={INPUT}
          >
            <option value="">(use yaml default)</option>
            <option value="none">none</option>
            <option value="zfs">zfs</option>
            <option value="btrfs">btrfs</option>
            <option value="restic">restic</option>
            <option value="proxmox">proxmox</option>
          </select>
        </Field>

        <div className="border-t border-border pt-4">
          <h3 className="mb-2 text-sm font-semibold">Proxmox VE</h3>
          <p className="mb-3 text-xs text-muted-foreground">
            Only required when <code>backend = proxmox</code>. Use a scoped
            PVE API token (Datacenter → Permissions → API Tokens) rather than
            a root password.
          </p>
          <div className="space-y-3">
            <Field label="URL">
              <input
                type="url"
                value={form.url}
                onChange={(e) => setForm({ ...form, url: e.target.value })}
                className={INPUT}
                placeholder="https://pve.local:8006"
              />
            </Field>
            <Field label="API token (user@realm!tokenid=secret)">
              <input
                type="password"
                value={form.token}
                onChange={(e) => setForm({ ...form, token: e.target.value })}
                className={INPUT}
                placeholder="bulwark@pve!ci=…"
                autoComplete="off"
              />
              <p className="mt-1 text-xs text-muted-foreground">
                Saved tokens display as <code>***</code> on edit — leave
                untouched to preserve, type a new value to replace, or empty
                to clear.
              </p>
            </Field>
            <div className="grid grid-cols-3 gap-3">
              <div className="col-span-2">
                <Field label="Node">
                  <input
                    type="text"
                    value={form.node}
                    onChange={(e) => setForm({ ...form, node: e.target.value })}
                    className={INPUT}
                    placeholder="pve01"
                  />
                </Field>
              </div>
              <Field label="VMID">
                <input
                  type="number"
                  min={1}
                  value={form.vmid}
                  onChange={(e) => setForm({ ...form, vmid: e.target.value })}
                  className={INPUT}
                  placeholder="100"
                />
              </Field>
            </div>
            <Field label="Kind">
              <select
                value={form.kind}
                onChange={(e) => setForm({ ...form, kind: e.target.value })}
                className={INPUT}
              >
                <option value="lxc">lxc (Linux container)</option>
                <option value="qemu">qemu (full VM)</option>
              </select>
            </Field>
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={form.insecureTLS}
                onChange={(e) => setForm({ ...form, insecureTLS: e.target.checked })}
              />
              Skip TLS verification (homelab self-signed certs)
            </label>
          </div>
        </div>

        {error && (
          <p className="text-sm text-red-600" role="alert">
            {error}
          </p>
        )}
        <div className="flex items-center justify-end">
          <Button variant="primary" onClick={() => void save()} disabled={busy}>
            {busy ? <Spinner /> : null}
            Save snapshot overrides
          </Button>
        </div>
      </CardBody>
    </Card>
  );
}
