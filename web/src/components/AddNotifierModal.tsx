import { useState } from "react";
import { Button } from "@/components/ui/Button";
import { Spinner } from "@/components/ui/Spinner";
import { useCreateNotifier, useTestEphemeralNotifier } from "@/lib/hooks";
import type { NotifierCreateRequest, NotifierKind } from "@/lib/types";

interface Props {
  open: boolean;
  onClose: () => void;
  onCreated: () => void;
}

type FormState = {
  name: string;
  kind: NotifierKind;
  minLevel: "safe" | "review" | "breaking";
  webhookURL: string;
  slackChannel: string;
  smtpHost: string;
  smtpPort: string;
  smtpUsername: string;
  smtpPassword: string;
  smtpFrom: string;
  smtpTo: string;
  smtpTLS: boolean;
  haURL: string;
  haToken: string;
};

const INITIAL: FormState = {
  name: "",
  kind: "slack",
  minLevel: "review",
  webhookURL: "",
  slackChannel: "",
  smtpHost: "",
  smtpPort: "587",
  smtpUsername: "",
  smtpPassword: "",
  smtpFrom: "",
  smtpTo: "",
  smtpTLS: true,
  haURL: "",
  haToken: "",
};

/**
 * AddNotifierModal renders an inline modal that captures the per-type
 * fields needed to create a notifier. The "Send test" button uses the
 * ephemeral test endpoint (no persistence) so the operator can confirm
 * delivery before saving. "Save" persists via POST /api/v1/notifiers
 * and triggers a registry reload daemon-side.
 */
export function AddNotifierModal({ open, onClose, onCreated }: Props) {
  const [form, setForm] = useState<FormState>(INITIAL);
  const { create, busy: saving, error: createError } = useCreateNotifier();
  const { send: testSend, busy: testing, error: testError, ok: testOk } = useTestEphemeralNotifier();

  if (!open) return null;

  function reset() {
    setForm(INITIAL);
  }

  function buildRequest(): NotifierCreateRequest | null {
    if (!form.name.trim()) return null;
    const base = {
      name: form.name.trim(),
      kind: form.kind,
      min_level: form.minLevel,
      enabled: true,
    };
    switch (form.kind) {
      case "slack":
        if (!form.webhookURL.trim()) return null;
        return {
          ...base,
          slack: {
            webhook_url: form.webhookURL.trim(),
            channel: form.slackChannel.trim() || undefined,
          },
        };
      case "discord":
        if (!form.webhookURL.trim()) return null;
        return { ...base, discord: { webhook_url: form.webhookURL.trim() } };
      case "teams":
        if (!form.webhookURL.trim()) return null;
        return { ...base, teams: { webhook_url: form.webhookURL.trim() } };
      case "homeassistant":
        if (!form.haURL.trim() || !form.haToken.trim()) return null;
        return {
          ...base,
          homeassistant: {
            url: form.haURL.trim(),
            token: form.haToken.trim(),
          },
        };
      case "smtp": {
        const port = parseInt(form.smtpPort, 10);
        if (!form.smtpHost.trim() || isNaN(port) || !form.smtpFrom.trim() || !form.smtpTo.trim()) {
          return null;
        }
        return {
          ...base,
          smtp: {
            host: form.smtpHost.trim(),
            port,
            username: form.smtpUsername.trim() || undefined,
            password: form.smtpPassword.trim() || undefined,
            from: form.smtpFrom.trim(),
            to: form.smtpTo.split(",").map((s) => s.trim()).filter(Boolean),
            tls: form.smtpTLS,
          },
        };
      }
    }
  }

  async function handleTest() {
    const req = buildRequest();
    if (!req) return;
    await testSend(req);
  }

  async function handleSave() {
    const req = buildRequest();
    if (!req) return;
    try {
      await create(req);
      onCreated();
      reset();
      onClose();
    } catch {
      // createError is rendered inline.
    }
  }

  function handleClose() {
    reset();
    onClose();
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4"
      role="dialog"
      aria-modal="true"
    >
      <div className="w-full max-w-lg rounded-lg border border-border bg-background p-6 shadow-lg">
        <h2 className="text-lg font-semibold tracking-tight">Add notifier</h2>
        <p className="mt-1 text-xs text-muted-foreground">
          New notifiers persist to the encrypted config store at
          <code className="mx-1">{"<datadir>/config.enc"}</code>. The daemon picks them up immediately — no restart required.
        </p>

        <div className="mt-4 space-y-3">
          <Field label="Name">
            <input
              type="text"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              className={INPUT}
              placeholder="ops-channel"
            />
          </Field>
          <Field label="Type">
            <select
              value={form.kind}
              onChange={(e) => setForm({ ...form, kind: e.target.value as NotifierKind })}
              className={INPUT}
            >
              <option value="slack">Slack</option>
              <option value="discord">Discord</option>
              <option value="teams">Microsoft Teams</option>
              <option value="smtp">SMTP / Email</option>
              <option value="homeassistant">Home Assistant</option>
            </select>
          </Field>
          <Field label="Minimum risk level">
            <select
              value={form.minLevel}
              onChange={(e) => setForm({ ...form, minLevel: e.target.value as FormState["minLevel"] })}
              className={INPUT}
            >
              <option value="safe">safe (all updates)</option>
              <option value="review">review (default)</option>
              <option value="breaking">breaking (only major / breaking)</option>
            </select>
          </Field>

          {(form.kind === "slack" || form.kind === "discord" || form.kind === "teams") && (
            <Field label="Webhook URL">
              <input
                type="url"
                value={form.webhookURL}
                onChange={(e) => setForm({ ...form, webhookURL: e.target.value })}
                className={INPUT}
                placeholder="https://hooks.example.com/services/..."
              />
            </Field>
          )}
          {form.kind === "slack" && (
            <Field label="Channel override (optional)">
              <input
                type="text"
                value={form.slackChannel}
                onChange={(e) => setForm({ ...form, slackChannel: e.target.value })}
                className={INPUT}
                placeholder="#alerts"
              />
            </Field>
          )}

          {form.kind === "homeassistant" && (
            <>
              <Field label="Home Assistant URL">
                <input
                  type="url"
                  value={form.haURL}
                  onChange={(e) => setForm({ ...form, haURL: e.target.value })}
                  className={INPUT}
                  placeholder="http://homeassistant.local:8123"
                />
              </Field>
              <Field label="Long-lived access token">
                <input
                  type="password"
                  value={form.haToken}
                  onChange={(e) => setForm({ ...form, haToken: e.target.value })}
                  className={INPUT}
                />
              </Field>
            </>
          )}

          {form.kind === "smtp" && (
            <>
              <div className="grid grid-cols-3 gap-3">
                <div className="col-span-2">
                  <Field label="SMTP host">
                    <input
                      type="text"
                      value={form.smtpHost}
                      onChange={(e) => setForm({ ...form, smtpHost: e.target.value })}
                      className={INPUT}
                      placeholder="smtp.example.com"
                    />
                  </Field>
                </div>
                <Field label="Port">
                  <input
                    type="number"
                    value={form.smtpPort}
                    onChange={(e) => setForm({ ...form, smtpPort: e.target.value })}
                    className={INPUT}
                  />
                </Field>
              </div>
              <Field label="Username (optional)">
                <input
                  type="text"
                  value={form.smtpUsername}
                  onChange={(e) => setForm({ ...form, smtpUsername: e.target.value })}
                  className={INPUT}
                />
              </Field>
              <Field label="Password (optional)">
                <input
                  type="password"
                  value={form.smtpPassword}
                  onChange={(e) => setForm({ ...form, smtpPassword: e.target.value })}
                  className={INPUT}
                />
              </Field>
              <Field label="From address">
                <input
                  type="email"
                  value={form.smtpFrom}
                  onChange={(e) => setForm({ ...form, smtpFrom: e.target.value })}
                  className={INPUT}
                  placeholder="bulwark@example.com"
                />
              </Field>
              <Field label="To addresses (comma-separated)">
                <input
                  type="text"
                  value={form.smtpTo}
                  onChange={(e) => setForm({ ...form, smtpTo: e.target.value })}
                  className={INPUT}
                  placeholder="ops@example.com, oncall@example.com"
                />
              </Field>
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={form.smtpTLS}
                  onChange={(e) => setForm({ ...form, smtpTLS: e.target.checked })}
                />
                Use STARTTLS
              </label>
            </>
          )}

          {createError && (
            <p className="text-sm text-red-600" role="alert">
              {createError}
            </p>
          )}
          {testError && (
            <p className="text-sm text-red-600" role="alert">
              Test failed: {testError}
            </p>
          )}
          {testOk && (
            <p className="text-sm text-emerald-700 dark:text-emerald-400">
              Test event delivered.
            </p>
          )}
        </div>

        <div className="mt-6 flex items-center justify-end gap-2">
          <Button variant="ghost" onClick={handleClose}>
            Cancel
          </Button>
          <Button
            variant="secondary"
            onClick={() => void handleTest()}
            disabled={testing || saving}
          >
            {testing ? <Spinner /> : null}
            Send test
          </Button>
          <Button
            variant="primary"
            onClick={() => void handleSave()}
            disabled={saving || testing}
          >
            {saving ? <Spinner /> : null}
            Save
          </Button>
        </div>
      </div>
    </div>
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
