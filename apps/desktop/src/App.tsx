import { FormEvent, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";

type HealthStatus = "healthy" | "drifted" | "invalid" | "missing" | "unknown";

type ProfileMeta = {
  id: string;
  name: string;
  account_label_masked: string;
  account_fingerprint: string;
  source_type: string;
  credential_mode: string;
  is_default: boolean;
  note?: string | null;
  health: {
    status: HealthStatus;
    detail: string;
  };
  created_at: string;
  last_synced_at?: string | null;
  last_used_at?: string | null;
};

type CurrentStatus = {
  live_session: {
    account_label_masked: string;
    account_fingerprint: string;
    source_type: string;
    credential_mode: string;
    last_refresh_at?: string | null;
  };
  active_profile?: ProfileMeta | null;
  sync_state: {
    status: "no_active_profile" | "in_sync" | "needs_sync" | "unknown";
    detail: string;
  };
};

type DashboardData = {
  current: CurrentStatus;
  doctor: {
    operating_system: string;
    codex_home: string;
    data_dir: string;
    auth_file: {
      path: string;
      exists: boolean;
      readable: boolean;
    };
    discovery_rule_count: number;
    live_session: {
      detected: boolean;
      detail: string;
      account_label_masked?: string | null;
      source_type?: string | null;
      credential_mode?: string | null;
    };
    discovery_trace: {
      matched_count: number;
      missing_input_count: number;
      lookup_missed_count: number;
      blocked_count: number;
      detail: string;
      entries: Array<{
        rule_name: string;
        service?: string | null;
        account_label_masked?: string | null;
        label?: string | null;
        status: string;
        detail: string;
      }>;
    };
    switch_probes: {
      detail: string;
      data_dir_write: {
        ok: boolean;
        detail: string;
      };
      lock_acquire: {
        ok: boolean;
        detail: string;
      };
      atomic_swap: {
        ok: boolean;
        detail: string;
      };
    };
    stores: Array<{
      name: string;
      supported: boolean;
      available: boolean;
      detail: string;
    }>;
    recovery: {
      pending_count: number;
      rollback_required_count: number;
      detail: string;
      transactions: Array<{
        txn_id: string;
        started_at: string;
        phase: string;
        rollback_required: boolean;
      }>;
    };
    profile_readiness: Array<{
      profile_name: string;
      account_label_masked: string;
      credential_mode: string;
      status: "ready" | "warning" | "blocked";
      blocker_count: number;
      warning_count: number;
      detail: string;
      blockers: string[];
      warnings: string[];
      source_operating_system: string;
      source_system_store_name?: string | null;
    }>;
    store_usage: Array<{
      store_name: string;
      profile_count: number;
      ready_count: number;
      warning_count: number;
      blocked_count: number;
      supported?: boolean | null;
      available?: boolean | null;
      detail: string;
    }>;
    validation: {
      status: "ready" | "file_only" | "blocked";
      detail: string;
      active_store_name?: string | null;
      ready_profile_count: number;
      warning_profile_count: number;
      blocked_profile_count: number;
      mixed_profile_count: number;
      next_steps: string[];
    };
    recommended_actions: string[];
  };
  profiles: ProfileMeta[];
  logs: string;
};

type CheckReport = {
  detail: string;
  drifted: boolean;
  profile: ProfileMeta;
  preflight: {
    ready: boolean;
    required_file_entries: number;
    required_system_entries: number;
    blockers: string[];
    warnings: string[];
    detail: string;
  };
};

type RecoveryReport = {
  recovered_count: number;
  removed_count: number;
  detail: string;
  transactions: Array<{
    txn_id: string;
    started_at: string;
    phase: string;
    rollback_required: boolean;
  }>;
};

export function App() {
  const [dashboard, setDashboard] = useState<DashboardData | null>(null);
  const [status, setStatus] = useState<string>("Loading current session...");
  const [error, setError] = useState<string | null>(null);
  const [saveName, setSaveName] = useState("");
  const [saveNote, setSaveNote] = useState("");
  const [saveDefault, setSaveDefault] = useState(false);
  const [transferPassphrase, setTransferPassphrase] = useState("");

  async function loadDashboard() {
    try {
      setError(null);
      const data = await invoke<DashboardData>("dashboard");
      setDashboard(data);
      setStatus("Dashboard refreshed.");
    } catch (err) {
      setError(String(err));
      setStatus("Unable to load the current session.");
    }
  }

  useEffect(() => {
    void loadDashboard();
  }, []);

  async function handleSave(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    try {
      const data = await invoke<DashboardData>("save_profile", {
        payload: {
          name: saveName,
          note: saveNote || null,
          makeDefault: saveDefault,
        },
      });
      setDashboard(data);
      setStatus(`Saved profile "${saveName}".`);
      setSaveName("");
      setSaveNote("");
      setSaveDefault(false);
    } catch (err) {
      setError(String(err));
    }
  }

  async function handleUse(name: string) {
    try {
      const data = await invoke<DashboardData>("use_profile", {
        payload: { name, makeDefault: false },
      });
      setDashboard(data);
      setStatus(`Switched to "${name}".`);
    } catch (err) {
      setError(String(err));
    }
  }

  async function handleSync() {
    try {
      const data = await invoke<DashboardData>("sync_active_profile");
      setDashboard(data);
      setStatus("Synced the active profile.");
    } catch (err) {
      setError(String(err));
    }
  }

  async function handleCheck(name: string) {
    try {
      const report = await invoke<CheckReport>("check_profile", { name });
      const summary = [
        report.detail,
        report.preflight.detail,
        ...report.preflight.blockers.map((blocker) => `Blocker: ${blocker}`),
        ...report.preflight.warnings.map((warning) => `Warning: ${warning}`),
      ].join(" ");
      setStatus(summary);
      await loadDashboard();
    } catch (err) {
      setError(String(err));
    }
  }

  async function handleSetDefault(name: string) {
    try {
      const data = await invoke<DashboardData>("set_default_profile", { name });
      setDashboard(data);
      setStatus(`Marked "${name}" as the default profile.`);
    } catch (err) {
      setError(String(err));
    }
  }

  async function handleRename(oldName: string) {
    const newName = window.prompt("Rename profile", oldName)?.trim();
    if (!newName || newName === oldName) {
      return;
    }

    try {
      const data = await invoke<DashboardData>("rename_profile", {
        payload: { oldName, newName },
      });
      setDashboard(data);
      setStatus(`Renamed "${oldName}" to "${newName}".`);
    } catch (err) {
      setError(String(err));
    }
  }

  async function handleDelete(name: string) {
    if (!window.confirm(`Delete profile "${name}"? This removes the saved snapshot.`)) {
      return;
    }

    try {
      const data = await invoke<DashboardData>("delete_profile", { name });
      setDashboard(data);
      setStatus(`Deleted profile "${name}".`);
    } catch (err) {
      setError(String(err));
    }
  }

  async function handleExport(name: string) {
    if (!transferPassphrase.trim()) {
      setError("Enter a transfer passphrase before exporting or importing.");
      return;
    }

    try {
      const output = await save({
        defaultPath: `${name}.cxswitch`,
        filters: [{ name: "Session Archives", extensions: ["cxswitch"] }],
      });
      if (!output) {
        return;
      }

      const archive = await invoke<string>("export_profile", {
        payload: {
          name,
          passphrase: transferPassphrase,
          output,
        },
      });
      setStatus(`Exported "${name}" to ${archive}.`);
    } catch (err) {
      setError(String(err));
    }
  }

  async function handleImport() {
    if (!transferPassphrase.trim()) {
      setError("Enter a transfer passphrase before exporting or importing.");
      return;
    }

    try {
      const path = await open({
        multiple: false,
        directory: false,
        filters: [{ name: "Session Archives", extensions: ["cxswitch"] }],
      });
      if (!path || Array.isArray(path)) {
        return;
      }

      const data = await invoke<DashboardData>("import_profile", {
        payload: {
          path,
          passphrase: transferPassphrase,
        },
      });
      setDashboard(data);
      setStatus(`Imported profile archive from ${path}.`);
    } catch (err) {
      setError(String(err));
    }
  }

  async function handleExportDiagnostics() {
    try {
      const output = await save({
        defaultPath: "session-manager-diagnostics.json",
        filters: [{ name: "Diagnostic Bundles", extensions: ["json"] }],
      });
      if (!output) {
        return;
      }

      const bundle = await invoke<string>("export_diagnostic_bundle", {
        payload: { output },
      });
      setStatus(`Exported a diagnostic bundle to ${bundle}.`);
    } catch (err) {
      setError(String(err));
    }
  }

  async function handleRecover() {
    try {
      const report = await invoke<RecoveryReport>("recover_pending_transactions");
      const data = await invoke<DashboardData>("dashboard");
      setDashboard(data);
      setStatus(report.detail);
    } catch (err) {
      setError(String(err));
    }
  }

  return (
    <main className="shell">
      <section className="hero">
        <div>
          <p className="eyebrow">Codex Local Session Manager</p>
          <h1>Keep official Codex sessions organized across local profiles.</h1>
          <p className="hero-copy">
            Save the current official login state, switch profiles with rollback
            protection, and sync refreshed tokens back into the right profile.
          </p>
        </div>
        <div className="hero-card">
          <div className="stat-label">Current Account</div>
          <div className="stat-value">
            {dashboard?.current.live_session.account_label_masked ?? "Unavailable"}
          </div>
          <div className="stat-meta">
            <span className="badge subtle">
              {dashboard?.current.live_session.source_type ?? "unknown"}
            </span>
            <span className="badge subtle">
              {dashboard?.current.live_session.credential_mode ?? "unknown"}
            </span>
          </div>
          <div className="stat-label">Active Profile</div>
          <div className="stat-value">
            {dashboard?.current.active_profile?.name ?? "None"}
          </div>
          <div className={`sync-pill sync-${dashboard?.current.sync_state.status ?? "unknown"}`}>
            {dashboard?.current.sync_state.status ?? "unknown"}
          </div>
          <p className="sync-detail">
            {dashboard?.current.sync_state.detail ??
              "No active profile is currently bound to the live session."}
          </p>
          <button
            className="primary"
            disabled={!dashboard?.current.active_profile}
            onClick={() => void handleSync()}
          >
            {dashboard?.current.sync_state.status === "needs_sync"
              ? "Sync Refreshed Session"
              : "Sync Active Profile"}
          </button>
        </div>
      </section>

      <section className="grid">
        <article className="panel">
          <div className="panel-header">
            <h2>Save Current Session</h2>
            <button className="ghost" onClick={() => void loadDashboard()}>
              Refresh
            </button>
          </div>
          <form className="save-form" onSubmit={handleSave}>
            <label>
              Profile name
              <input
                value={saveName}
                onChange={(event) => setSaveName(event.target.value)}
                placeholder="personal"
                required
              />
            </label>
            <label>
              Note
              <textarea
                value={saveNote}
                onChange={(event) => setSaveNote(event.target.value)}
                placeholder="What is this account for?"
                rows={3}
              />
            </label>
            <label className="checkbox">
              <input
                checked={saveDefault}
                onChange={(event) => setSaveDefault(event.target.checked)}
                type="checkbox"
              />
              Mark as default profile
            </label>
            <button className="primary" type="submit">
              Save Profile
            </button>
          </form>
          <div className="transfer-tools">
            <label>
              Transfer passphrase
              <input
                type="password"
                value={transferPassphrase}
                onChange={(event) => setTransferPassphrase(event.target.value)}
                placeholder="Used for export and import"
              />
            </label>
            <button className="ghost" onClick={() => void handleImport()} type="button">
              Import Profile Archive
            </button>
          </div>
          <p className="status">{status}</p>
          {error ? <p className="error">{error}</p> : null}
        </article>

        <article className="panel">
          <div className="panel-header">
            <h2>Profiles</h2>
            <span>{dashboard?.profiles.length ?? 0} saved</span>
          </div>
          <div className="profile-list">
            {dashboard?.profiles.map((profile) => (
              <div className="profile-card" key={profile.id}>
                <div className="profile-topline">
                  <h3>{profile.name}</h3>
                  <div className="profile-badges">
                    <span className="badge subtle">{profile.source_type}</span>
                    <span className="badge subtle">{profile.credential_mode}</span>
                    {profile.is_default ? <span className="badge">Default</span> : null}
                  </div>
                </div>
                <p className="muted">{profile.account_label_masked}</p>
                <p className={`health health-${profile.health.status}`}>
                  {profile.health.status}: {profile.health.detail}
                </p>
                <div className="actions">
                  <button className="primary" onClick={() => void handleUse(profile.name)}>
                    Use
                  </button>
                  <button className="ghost" onClick={() => void handleCheck(profile.name)}>
                    Health Check
                  </button>
                  <button
                    className="ghost"
                    disabled={profile.is_default}
                    onClick={() => void handleSetDefault(profile.name)}
                  >
                    Set Default
                  </button>
                  <button className="ghost" onClick={() => void handleRename(profile.name)}>
                    Rename
                  </button>
                  <button className="ghost" onClick={() => void handleExport(profile.name)}>
                    Export
                  </button>
                  <button className="danger" onClick={() => void handleDelete(profile.name)}>
                    Delete
                  </button>
                </div>
              </div>
            ))}
            {!dashboard?.profiles.length ? (
              <p className="muted">No profiles yet. Save the current account to get started.</p>
            ) : null}
          </div>
        </article>
      </section>

      <section className="panel">
        <div className="panel-header">
          <h2>Platform Readiness</h2>
          <div className="actions">
            <span>{dashboard?.doctor.operating_system ?? "unknown"}</span>
            <button className="ghost" onClick={() => void handleExportDiagnostics()}>
              Export Diagnostics
            </button>
          </div>
        </div>
        <div className="doctor-grid">
          <div className="doctor-card">
            <div className="stat-label">Auth File</div>
            <div className="doctor-path">{dashboard?.doctor.auth_file.path ?? "Unavailable"}</div>
            <p className="muted">
              exists={String(dashboard?.doctor.auth_file.exists ?? false)} readable=
              {String(dashboard?.doctor.auth_file.readable ?? false)}
            </p>
          </div>
          <div className="doctor-card">
            <div className="stat-label">Discovery Rules</div>
            <div className="stat-value">{dashboard?.doctor.discovery_rule_count ?? 0}</div>
            <p className="muted">
              {dashboard?.doctor.discovery_trace.detail ?? "No discovery trace detail."}
            </p>
          </div>
          <div className="doctor-card">
            <div className="stat-label">Recovery</div>
            <div className="stat-value">{dashboard?.doctor.recovery.pending_count ?? 0}</div>
            <p className="muted">{dashboard?.doctor.recovery.detail ?? "No recovery detail."}</p>
            <button
              className="ghost"
              disabled={!dashboard?.doctor.recovery.pending_count}
              onClick={() => void handleRecover()}
              type="button"
            >
              Recover Interrupted Switches
            </button>
          </div>
          <div className="doctor-card">
            <div className="stat-label">Switch Probes</div>
            <div className="stat-value">
              {dashboard?.doctor.switch_probes.detail ?? "No probe detail."}
            </div>
            <p className="muted">
              data_dir={String(dashboard?.doctor.switch_probes.data_dir_write.ok ?? false)} lock=
              {String(dashboard?.doctor.switch_probes.lock_acquire.ok ?? false)} atomic_swap=
              {String(dashboard?.doctor.switch_probes.atomic_swap.ok ?? false)}
            </p>
          </div>
          <div className="doctor-card">
            <div className="stat-label">Validation</div>
            <div className="profile-topline">
              <strong>{dashboard?.doctor.validation.status ?? "unknown"}</strong>
              <span
                className={`badge ${
                  dashboard?.doctor.validation.status === "ready"
                    ? "badge-ready"
                    : dashboard?.doctor.validation.status === "file_only"
                      ? "badge-warning"
                      : "badge-blocked"
                }`}
              >
                {dashboard?.doctor.validation.active_store_name ?? "file-backed"}
              </span>
            </div>
            <p className="muted">
              {dashboard?.doctor.validation.detail ?? "No validation readiness detail."}
            </p>
            <p className="muted">
              ready={dashboard?.doctor.validation.ready_profile_count ?? 0} warning=
              {dashboard?.doctor.validation.warning_profile_count ?? 0} blocked=
              {dashboard?.doctor.validation.blocked_profile_count ?? 0} mixed=
              {dashboard?.doctor.validation.mixed_profile_count ?? 0}
            </p>
          </div>
        </div>
        <div className="store-list">
          {dashboard?.doctor.stores.map((store) => (
            <div className="store-card" key={store.name}>
              <div className="profile-topline">
                <strong>{store.name}</strong>
                <span
                  className={`badge ${store.available ? "badge-ready" : "badge-idle"}`}
                >
                  {store.available ? "Ready" : store.supported ? "Blocked" : "Unsupported"}
                </span>
              </div>
              <p className="muted">{store.detail}</p>
            </div>
          ))}
        </div>
        {!!dashboard?.doctor.store_usage.length && (
          <div className="store-list">
            {dashboard.doctor.store_usage.map((usage) => (
              <div className="store-card" key={usage.store_name}>
                <div className="profile-topline">
                  <strong>{usage.store_name}</strong>
                  <span
                    className={`badge ${
                      usage.blocked_count > 0
                        ? "badge-blocked"
                        : usage.warning_count > 0
                          ? "badge-warning"
                          : "badge-ready"
                    }`}
                  >
                    {usage.blocked_count > 0
                      ? "blocked"
                      : usage.warning_count > 0
                        ? "warning"
                        : "ready"}
                  </span>
                </div>
                <p className="muted">
                  profiles={usage.profile_count} ready={usage.ready_count} warning=
                  {usage.warning_count} blocked={usage.blocked_count}
                </p>
                <p className="muted">
                  supported=
                  {usage.supported == null ? "-" : String(usage.supported)} available=
                  {usage.available == null ? "-" : String(usage.available)}
                </p>
                <p className="muted">{usage.detail}</p>
              </div>
            ))}
          </div>
        )}
        {!!dashboard?.doctor.profile_readiness.length && (
          <div className="store-list">
            {dashboard.doctor.profile_readiness.map((profile) => (
              <div className="store-card" key={profile.profile_name}>
                <div className="profile-topline">
                  <strong>{profile.profile_name}</strong>
                  <span
                    className={`badge ${
                      profile.status === "ready"
                        ? "badge-ready"
                        : profile.status === "warning"
                          ? "badge-warning"
                          : "badge-blocked"
                    }`}
                  >
                    {profile.status}
                  </span>
                </div>
                <p className="muted">
                  {profile.account_label_masked} · {profile.credential_mode} · source=
                  {profile.source_operating_system}
                  {profile.source_system_store_name
                    ? `/${profile.source_system_store_name}`
                    : ""}
                </p>
                <p className="muted">{profile.detail}</p>
                {!!profile.blockers.length && (
                  <p className="muted">
                    {profile.blockers.map((blocker) => `Blocker: ${blocker}`).join(" ")}
                  </p>
                )}
                {!!profile.warnings.length && (
                  <p className="muted">
                    {profile.warnings.map((warning) => `Warning: ${warning}`).join(" ")}
                  </p>
                )}
              </div>
            ))}
          </div>
        )}
        {!!dashboard?.doctor.recommended_actions.length && (
          <div className="doctor-actions">
            {dashboard.doctor.recommended_actions.map((action) => (
              <p className="muted" key={action}>
                {action}
              </p>
            ))}
          </div>
        )}
        {!!dashboard?.doctor.validation.next_steps.length && (
          <div className="doctor-actions">
            {dashboard.doctor.validation.next_steps.map((step) => (
              <p className="muted" key={step}>
                {step}
              </p>
            ))}
          </div>
        )}
        {!!dashboard?.doctor.discovery_trace.entries.length && (
          <div className="doctor-actions">
            {dashboard.doctor.discovery_trace.entries.map((entry) => (
              <p className="muted" key={`${entry.rule_name}-${entry.status}-${entry.service}`}>
                {entry.rule_name} · {entry.status} · {entry.service ?? "-"} ·{" "}
                {entry.account_label_masked ?? "-"}
              </p>
            ))}
          </div>
        )}
        {!!dashboard?.doctor.recovery.transactions.length && (
          <div className="doctor-actions">
            {dashboard.doctor.recovery.transactions.map((txn) => (
              <p className="muted" key={txn.txn_id}>
                {txn.txn_id} · {txn.phase} · rollback_required=
                {String(txn.rollback_required)}
              </p>
            ))}
          </div>
        )}
        <div className="doctor-actions">
          <p className="muted">{dashboard?.doctor.switch_probes.data_dir_write.detail}</p>
          <p className="muted">{dashboard?.doctor.switch_probes.lock_acquire.detail}</p>
          <p className="muted">{dashboard?.doctor.switch_probes.atomic_swap.detail}</p>
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <h2>Logs</h2>
          <span>Audit trail</span>
        </div>
        <pre className="logs">{dashboard?.logs || "No audit log entries yet."}</pre>
      </section>
    </main>
  );
}
