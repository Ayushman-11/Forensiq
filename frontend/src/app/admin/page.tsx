"use client";

import { useState, useEffect, useCallback } from "react";
import {
  Server,
  CheckCircle2,
  Cpu,
  Users,
  UserPlus,
  KeyRound,
  QrCode,
  Lock,
  LogOut,
  Power,
  RotateCcw,
  AlertTriangle,
  Loader2,
  Bell,
  Send,
  Trash2,
} from "lucide-react";
import { useAuth } from "@/context/AuthContext";
import { roleLabel } from "@/lib/roles";
import { apiFetch } from "@/lib/api";

interface UserRecord {
  id: string;
  email: string;
  role: string;
  is_active: boolean;
  mfa_enabled: boolean;
  created_at?: string;
}

export default function AdministrationPage() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  // System config state
  const [splunkHost, setSplunkHost] = useState("localhost");
  const [splunkPort, setSplunkPort] = useState("8089");
  const [aiModel, setAiModel] = useState("grok-beta");
  const [cacheTtl, setCacheTtl] = useState("86400");
  const [configSaved, setConfigSaved] = useState(false);

  // User management state
  const [users, setUsers] = useState<UserRecord[]>([]);
  const [loadingUsers, setLoadingUsers] = useState(false);
  const [userError, setUserError] = useState<string | null>(null);
  const [userSuccess, setUserSuccess] = useState<string | null>(null);

  // Create user modal / fields
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newEmail, setNewEmail] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newRole, setNewRole] = useState("analyst");
  const [creatingUser, setCreatingUser] = useState(false);

  // Notification channels state
  interface NotificationChannel {
    id: string;
    name: string;
    channel_type: "slack" | "teams" | "pagerduty" | "opsgenie" | "email";
    enabled: boolean;
    webhook_url?: string;
    routing_key?: string;
    api_key?: string;
    email_recipients?: string[];
    min_severity: string;
    quiet_hours_enabled: boolean;
  }
  const [channels, setChannels] = useState<NotificationChannel[]>([]);
  const [, setLoadingChannels] = useState(false);
  const [showAddChannelModal, setShowAddChannelModal] = useState(false);
  const [newChannelName, setNewChannelName] = useState("");
  const [newChannelType, setNewChannelType] = useState<"slack" | "teams" | "pagerduty" | "opsgenie" | "email">("slack");
  const [newWebhookUrl, setNewWebhookUrl] = useState("");
  const [newRoutingKey, setNewRoutingKey] = useState("");
  const [newEmailRecipients, setNewEmailRecipients] = useState("");
  const [newQuietHours, setNewQuietHours] = useState(false);
  const [testStatus, setTestStatus] = useState<string | null>(null);

  const loadChannels = useCallback(async () => {
    if (!isAdmin) return;
    setLoadingChannels(true);
    try {
      const res = await apiFetch("/api/v1/notifications/channels");
      if (res.ok) {
        const data = await res.json();
        setChannels(data);
      }
    } catch {
      // ignore
    } finally {
      setLoadingChannels(false);
    }
  }, [isAdmin]);

  const handleCreateChannel = async (e: React.FormEvent) => {
    e.preventDefault();
    setUserError(null);
    try {
      const body: Record<string, unknown> = {
        name: newChannelName,
        channel_type: newChannelType,
        min_severity: "medium",
        quiet_hours_enabled: newQuietHours,
      };
      if (newChannelType === "slack" || newChannelType === "teams") {
        body.webhook_url = newWebhookUrl;
      } else if (newChannelType === "pagerduty") {
        body.routing_key = newRoutingKey;
      } else if (newChannelType === "email") {
        body.email_recipients = newEmailRecipients.split(",").map(e => e.trim()).filter(Boolean);
      }
      const res = await apiFetch("/api/v1/notifications/channels", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || "Failed to create channel");
      }
      setUserSuccess(`Notification channel ${newChannelName} configured successfully.`);
      setShowAddChannelModal(false);
      setNewChannelName("");
      setNewWebhookUrl("");
      setNewRoutingKey("");
      setNewEmailRecipients("");
      void loadChannels();
      setTimeout(() => setUserSuccess(null), 4000);
    } catch (err: unknown) {
      setUserError(err instanceof Error ? err.message : "Error creating channel");
    }
  };

  const handleDeleteChannel = async (id: string) => {
    if (!confirm("Delete this notification channel?")) return;
    try {
      await apiFetch(`/api/v1/notifications/channels/${id}`, { method: "DELETE" });
      void loadChannels();
    } catch {
      // ignore
    }
  };

  const handleSendTestNotification = async (channelId?: string) => {
    setTestStatus("Sending test alert...");
    try {
      const res = await apiFetch("/api/v1/notifications/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel_id: channelId }),
      });
      if (res.ok) {
        setTestStatus("Test alert successfully dispatched!");
        setTimeout(() => setTestStatus(null), 3000);
      } else {
        setTestStatus("Test dispatch failed.");
      }
    } catch {
      setTestStatus("Failed to send test alert.");
    }
  };

  // Password reset modal / fields
  const [resetTargetUser, setResetTargetUser] = useState<UserRecord | null>(null);
  const [resetPasswordVal, setResetPasswordVal] = useState("");
  const [resettingPassword, setResettingPassword] = useState(false);

  // MFA Setup state
  const [mfaSecret, setMfaSecret] = useState<string | null>(null);
  const [mfaUri, setMfaUri] = useState<string | null>(null);
  const [mfaCode, setMfaCode] = useState("");
  const [mfaLoading, setMfaLoading] = useState(false);
  const [mfaStatusMsg, setMfaStatusMsg] = useState<string | null>(null);

  // Load user directory if admin
  const loadUsers = useCallback(async () => {
    if (!isAdmin) return;
    setLoadingUsers(true);
    setUserError(null);
    try {
      const res = await apiFetch("/api/v1/admin/users");
      if (res.ok) {
        const data = await res.json();
        setUsers(data);
      } else {
        const err = await res.json().catch(() => ({}));
        setUserError(err.detail || "Failed to load organization users");
      }
    } catch {
      setUserError("Network error loading users");
    } finally {
      setLoadingUsers(false);
    }
  }, [isAdmin]);

  useEffect(() => {
    let active = true;
    if (isAdmin) {
      void (async () => {
        try {
          void loadChannels();
          const res = await apiFetch("/api/v1/admin/users");
          if (res.ok && active) {
            const data = await res.json();
            setUsers(data);
          }
        } catch {
          // ignore mount fetch errors
        }
      })();
    }
    return () => {
      active = false;
    };
  }, [isAdmin]);

  const handleConfigSave = (e: React.FormEvent) => {
    e.preventDefault();
    setConfigSaved(true);
    setTimeout(() => setConfigSaved(false), 3000);
  };

  // Create user submit
  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreatingUser(true);
    setUserError(null);
    try {
      const res = await apiFetch("/api/v1/admin/users", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: newEmail,
          password: newPassword,
          role: newRole,
        }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || "Failed to create user");
      }

      setUserSuccess(`User ${newEmail} created successfully.`);
      setShowCreateModal(false);
      setNewEmail("");
      setNewPassword("");
      void loadUsers();
      setTimeout(() => setUserSuccess(null), 4000);
    } catch (err: unknown) {
      setUserError(err instanceof Error ? err.message : "Error creating user");
    } finally {
      setCreatingUser(false);
    }
  };

  // Toggle user status (Enable / Disable)
  const handleToggleStatus = async (target: UserRecord) => {
    setUserError(null);
    try {
      const res = await apiFetch(`/api/v1/admin/users/${target.id}/status`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ is_active: !target.is_active }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || "Failed to update status");
      }

      setUserSuccess(`User ${target.email} is now ${!target.is_active ? "Active" : "Disabled"}.`);
      void loadUsers();
      setTimeout(() => setUserSuccess(null), 4000);
    } catch (err: unknown) {
      setUserError(err instanceof Error ? err.message : "Error updating user status");
    }
  };

  // Terminate all sessions for a user
  const handleTerminateSessions = async (target: UserRecord) => {
    if (!confirm(`Force logout all active sessions for ${target.email}?`)) return;
    setUserError(null);
    try {
      const res = await apiFetch(`/api/v1/admin/users/${target.id}/terminate-sessions`, {
        method: "POST",
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || "Failed to terminate sessions");
      }

      const data = await res.json();
      setUserSuccess(`Terminated ${data.revoked_count} active sessions for ${target.email}.`);
      setTimeout(() => setUserSuccess(null), 4000);
    } catch (err: unknown) {
      setUserError(err instanceof Error ? err.message : "Error terminating sessions");
    }
  };

  // Reset user password
  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!resetTargetUser) return;
    setResettingPassword(true);
    setUserError(null);
    try {
      const res = await apiFetch(`/api/v1/admin/users/${resetTargetUser.id}/reset-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: resetPasswordVal }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || "Failed to reset password");
      }

      setUserSuccess(`Password for ${resetTargetUser.email} has been reset.`);
      setResetTargetUser(null);
      setResetPasswordVal("");
      setTimeout(() => setUserSuccess(null), 4000);
    } catch (err: unknown) {
      setUserError(err instanceof Error ? err.message : "Error resetting password");
    } finally {
      setResettingPassword(false);
    }
  };

  // Initiate TOTP MFA Setup for currently logged in user
  const handleStartMfaSetup = async () => {
    setMfaLoading(true);
    setMfaStatusMsg(null);
    try {
      const res = await apiFetch("/api/v1/auth/mfa/setup", { method: "POST" });
      if (res.ok) {
        const data = await res.json();
        setMfaSecret(data.secret);
        setMfaUri(data.provisioning_uri);
      } else {
        const err = await res.json().catch(() => ({}));
        setMfaStatusMsg(`Error: ${err.detail || "Unable to start MFA setup"}`);
      }
    } catch {
      setMfaStatusMsg("Network error initiating MFA setup");
    } finally {
      setMfaLoading(false);
    }
  };

  // Confirm TOTP code & enable
  const handleConfirmMfa = async (e: React.FormEvent) => {
    e.preventDefault();
    setMfaLoading(true);
    setMfaStatusMsg(null);
    try {
      const res = await apiFetch("/api/v1/auth/mfa/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: mfaCode }),
      });

      if (res.ok) {
        setMfaStatusMsg("Two-Factor Authentication (TOTP) successfully activated!");
        setMfaSecret(null);
        setMfaUri(null);
        setMfaCode("");
        void loadUsers();
      } else {
        const err = await res.json().catch(() => ({}));
        setMfaStatusMsg(`Verification failed: ${err.detail || "Invalid code"}`);
      }
    } catch {
      setMfaStatusMsg("Network error verifying MFA token");
    } finally {
      setMfaLoading(false);
    }
  };

  return (
    <div className="mx-auto flex max-w-[1520px] flex-col gap-6 pb-12">
      {/* Header */}
      <header className="flex flex-wrap items-center justify-between gap-4 border-b border-[var(--border-color)] pb-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[var(--text-primary)]">
            Administration & Security Operations
          </h1>
          <p className="text-xs text-[var(--text-secondary)] mt-0.5">
            Platform posture · Multi-tenant user directory, session controls, SIEM and MFA configuration.
          </p>
        </div>
        {isAdmin && (
          <button
            onClick={() => setShowCreateModal(true)}
            className="button-primary text-xs flex items-center gap-1.5"
          >
            <UserPlus className="w-3.5 h-3.5" />
            <span>Invite SOC Analyst</span>
          </button>
        )}
      </header>

      {/* Alerts / Feedback */}
      {configSaved && (
        <div className="flex items-center gap-2 rounded border border-[#22C55E]/30 bg-[#22C55E]/10 px-3.5 py-2 text-xs font-medium text-[#22C55E]">
          <CheckCircle2 className="h-4 w-4 shrink-0" />
          <span>System configuration updated successfully.</span>
        </div>
      )}

      {userSuccess && (
        <div className="flex items-center gap-2 rounded border border-[#22C55E]/30 bg-[#22C55E]/10 px-3.5 py-2 text-xs font-medium text-[#22C55E]">
          <CheckCircle2 className="h-4 w-4 shrink-0" />
          <span>{userSuccess}</span>
        </div>
      )}

      {userError && (
        <div className="flex items-center gap-2 rounded border border-[#FF1E56]/30 bg-[#FF1E56]/10 px-3.5 py-2 text-xs font-medium text-[#FF1E56]">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          <span>{userError}</span>
        </div>
      )}

      {/* Grid: System & AI Config */}
      <form onSubmit={handleConfigSave} className="grid gap-5 lg:grid-cols-2">
        {/* SIEM Splunk Connection Settings */}
        <div className="card p-4 space-y-4">
          <div className="flex items-center gap-2 border-b border-[var(--border-color)] pb-2.5">
            <Server className="w-4 h-4 text-[var(--text-muted)]" />
            <h2 className="text-sm font-semibold text-[var(--text-primary)]">SIEM Connection (Splunk)</h2>
          </div>

          <div className="space-y-3 text-xs">
            <div className="flex flex-col gap-1">
              <label className="text-[11px] font-semibold text-[var(--text-muted)]">Splunk Host / Management URL</label>
              <input
                type="text"
                value={splunkHost}
                onChange={(e) => setSplunkHost(e.target.value)}
                className="field font-mono"
              />
            </div>

            <div className="flex flex-col gap-1">
              <label className="text-[11px] font-semibold text-[var(--text-muted)]">Management Port (REST API)</label>
              <input
                type="text"
                value={splunkPort}
                onChange={(e) => setSplunkPort(e.target.value)}
                className="field font-mono"
              />
            </div>

            <div className="flex items-center justify-between pt-2 border-t border-[var(--border-color)] text-xs">
              <span className="text-[var(--text-secondary)]">TLS Verification</span>
              <span className="font-mono text-[11px] font-semibold text-[#22C55E] flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-[#22C55E]" /> Enforced
              </span>
            </div>
          </div>
        </div>

        {/* AI Agent Engine Settings */}
        <div className="card p-4 space-y-4">
          <div className="flex items-center gap-2 border-b border-[var(--border-color)] pb-2.5">
            <Cpu className="w-4 h-4 text-[var(--text-muted)]" />
            <h2 className="text-sm font-semibold text-[var(--text-primary)]">AI Agent Pipeline Config</h2>
          </div>

          <div className="space-y-3 text-xs">
            <div className="flex flex-col gap-1">
              <label className="text-[11px] font-semibold text-[var(--text-muted)]">LLM Provider & Model</label>
              <select
                value={aiModel}
                onChange={(e) => setAiModel(e.target.value)}
                className="field font-mono cursor-pointer"
              >
                <option value="grok-beta">xAI Grok-Beta (Default)</option>
                <option value="gpt-4o">OpenAI GPT-4o</option>
                <option value="claude-3-5-sonnet">Anthropic Claude 3.5 Sonnet</option>
              </select>
            </div>

            <div className="flex flex-col gap-1">
              <label className="text-[11px] font-semibold text-[var(--text-muted)]">Threat Cache TTL (Seconds)</label>
              <input
                type="text"
                value={cacheTtl}
                onChange={(e) => setCacheTtl(e.target.value)}
                className="field font-mono"
              />
            </div>

            <div className="flex items-center justify-between pt-2 border-t border-[var(--border-color)] text-xs">
              <span className="text-[var(--text-secondary)]">LangGraph Agent Graph</span>
              <span className="font-mono text-[11px] font-semibold text-[#8B5CF6]">7 Active Pipeline Stages</span>
            </div>
          </div>
        </div>
      </form>

      {/* User Directory & RBAC Section */}
      <section className="card p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[var(--border-color)] pb-3">
          <div className="flex items-center gap-2">
            <Users className="w-4 h-4 text-[var(--text-muted)]" />
            <h2 className="text-sm font-semibold text-[var(--text-primary)]">SOC Team & User Access Control</h2>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => void loadUsers()}
              disabled={loadingUsers}
              className="text-xs px-2.5 py-1 rounded bg-[var(--surface-secondary)] border border-[var(--border-color)] text-[var(--text-secondary)] hover:text-white flex items-center gap-1 cursor-pointer"
            >
              <RotateCcw className={`w-3 h-3 ${loadingUsers ? "animate-spin" : ""}`} />
              <span>Refresh Directory</span>
            </button>
          </div>
        </div>

        {loadingUsers ? (
          <div className="py-8 flex justify-center items-center text-xs text-[var(--text-secondary)] gap-2">
            <Loader2 className="w-4 h-4 animate-spin text-[#FF1E56]" />
            <span>Loading user accounts...</span>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-[var(--border-color)] text-[10px] uppercase font-bold text-[var(--text-muted)]">
                  <th className="pb-2.5 font-semibold">User Email</th>
                  <th className="pb-2.5 font-semibold">Role</th>
                  <th className="pb-2.5 font-semibold">Status</th>
                  <th className="pb-2.5 font-semibold">MFA</th>
                  <th className="pb-2.5 font-semibold text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border-color)]">
                {users.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="py-4 text-center text-[var(--text-muted)]">
                      {isAdmin ? "No additional users registered in this tenant." : "Directory viewing restricted to Administrators."}
                    </td>
                  </tr>
                ) : (
                  users.map((u) => (
                    <tr key={u.id} className="hover:bg-[var(--surface-secondary)]/40 transition-colors">
                      <td className="py-2.5 font-mono text-[var(--text-primary)] flex items-center gap-2">
                        <span>{u.email}</span>
                        {u.id === user?.sub && (
                          <span className="text-[9px] bg-[#3B82F6]/20 text-[#3B82F6] px-1.5 py-0.5 rounded font-sans font-bold">
                            YOU
                          </span>
                        )}
                      </td>
                      <td className="py-2.5">
                        <span className="font-mono text-[11px] px-2 py-0.5 rounded border border-[var(--border-color)] bg-[var(--surface-secondary)] text-[var(--text-secondary)]">
                          {roleLabel(u.role)}
                        </span>
                      </td>
                      <td className="py-2.5">
                        {u.is_active ? (
                          <span className="inline-flex items-center gap-1 text-[#22C55E] text-[11px]">
                            <span className="w-1.5 h-1.5 rounded-full bg-[#22C55E]" /> Active
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-[#EF4444] text-[11px]">
                            <span className="w-1.5 h-1.5 rounded-full bg-[#EF4444]" /> Disabled
                          </span>
                        )}
                      </td>
                      <td className="py-2.5">
                        {u.mfa_enabled ? (
                          <span className="text-[#8B5CF6] text-[11px] font-semibold">TOTP Enabled</span>
                        ) : (
                          <span className="text-[var(--text-muted)] text-[11px]">None</span>
                        )}
                      </td>
                      <td className="py-2.5 text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            onClick={() => setResetTargetUser(u)}
                            title="Reset Password"
                            className="p-1 rounded hover:bg-[var(--surface-secondary)] text-[var(--text-muted)] hover:text-white"
                          >
                            <KeyRound className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => void handleTerminateSessions(u)}
                            title="Force Terminate All Sessions"
                            className="p-1 rounded hover:bg-[var(--surface-secondary)] text-[var(--text-muted)] hover:text-[#F59E0B]"
                          >
                            <LogOut className="w-3.5 h-3.5" />
                          </button>
                          {u.id !== user?.sub && (
                            <button
                              onClick={() => void handleToggleStatus(u)}
                              title={u.is_active ? "Disable User Account" : "Enable User Account"}
                              className={`p-1 rounded hover:bg-[var(--surface-secondary)] ${
                                u.is_active ? "text-[var(--text-muted)] hover:text-[#EF4444]" : "text-[#22C55E]"
                              }`}
                            >
                              <Power className="w-3.5 h-3.5" />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* SOC Notifications & Escalation Routing */}
      <section className="card p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[var(--border-color)] pb-3">
          <div className="flex items-center gap-2">
            <Bell className="w-4 h-4 text-[#F59E0B]" />
            <h2 className="text-sm font-semibold text-[var(--text-primary)]">
              Real-Time Notifications & On-Call Alerts (SLA, Criticals, Escalations)
            </h2>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => void handleSendTestNotification()}
              className="text-xs px-2.5 py-1 rounded bg-[var(--surface-secondary)] border border-[var(--border-color)] text-[var(--text-secondary)] hover:text-white flex items-center gap-1.5 cursor-pointer"
            >
              <Send className="w-3 h-3 text-[#3B82F6]" />
              <span>Test Broadcast</span>
            </button>
            {isAdmin && (
              <button
                type="button"
                onClick={() => setShowAddChannelModal(true)}
                className="button-primary text-xs flex items-center gap-1"
              >
                <span>+ Add Channel</span>
              </button>
            )}
          </div>
        </div>

        {testStatus && (
          <div className="p-2.5 rounded bg-[#3B82F6]/10 border border-[#3B82F6]/30 text-[#3B82F6] text-xs">
            {testStatus}
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs mb-3">
          <div className="p-3 rounded bg-[var(--surface-secondary)] border border-[var(--border-color)] space-y-1">
            <span className="text-[10px] text-[var(--text-muted)] uppercase font-bold">New Critical Alert</span>
            <p className="text-[11px] text-[var(--text-secondary)]">Immediate dispatch across active channels.</p>
          </div>
          <div className="p-3 rounded bg-[var(--surface-secondary)] border border-[var(--border-color)] space-y-1">
            <span className="text-[10px] text-[var(--text-muted)] uppercase font-bold">Unassigned Critical (&gt;15m)</span>
            <p className="text-[11px] text-[var(--text-secondary)]">Broadcasts escalation when criticals sit untouched.</p>
          </div>
          <div className="p-3 rounded bg-[var(--surface-secondary)] border border-[var(--border-color)] space-y-1">
            <span className="text-[10px] text-[var(--text-muted)] uppercase font-bold">SLA Acknowledge / Resolve</span>
            <p className="text-[11px] text-[var(--text-secondary)]">Alerts when timers (15m ack, 2h resolve) breach.</p>
          </div>
        </div>

        {channels.length === 0 ? (
          <div className="p-4 rounded border border-dashed border-[var(--border-color)] text-center text-xs text-[var(--text-muted)]">
            No notification channels configured. Add a Slack, Teams, PagerDuty, or Email channel to prevent alerts being missed overnight.
          </div>
        ) : (
          <div className="divide-y divide-[var(--border-color)]">
            {channels.map((ch) => (
              <div key={ch.id} className="py-2.5 flex items-center justify-between text-xs">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-[var(--text-primary)]">{ch.name}</span>
                    <span className="font-mono text-[10px] uppercase px-1.5 py-0.5 rounded bg-[var(--surface-secondary)] text-[var(--text-secondary)] border border-[var(--border-color)]">
                      {ch.channel_type}
                    </span>
                    {ch.quiet_hours_enabled && (
                      <span className="text-[10px] text-[#F59E0B]">(Quiet Hours Enabled)</span>
                    )}
                  </div>
                  <p className="text-[11px] text-[var(--text-muted)] mt-0.5">
                    Subscribed: Critical Alerts, SLA Breaches, Escalations
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => void handleSendTestNotification(ch.id)}
                    className="p-1 rounded text-[var(--text-muted)] hover:text-white"
                    title="Send Test Notification"
                  >
                    <Send className="w-3.5 h-3.5" />
                  </button>
                  {isAdmin && (
                    <button
                      type="button"
                      onClick={() => void handleDeleteChannel(ch.id)}
                      className="p-1 rounded text-[var(--text-muted)] hover:text-[#EF4444]"
                      title="Delete Channel"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Two-Factor Authentication (TOTP) Profile Setup */}
      <section className="card p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-[var(--border-color)] pb-3">
          <div className="flex items-center gap-2">
            <Lock className="w-4 h-4 text-[var(--text-muted)]" />
            <h2 className="text-sm font-semibold text-[var(--text-primary)]">
              Two-Factor Authentication (RFC 6238 TOTP)
            </h2>
          </div>
          <span className="text-xs text-[var(--text-muted)]">Account Security</span>
        </div>

        {mfaStatusMsg && (
          <div className="p-3 rounded text-xs border border-[#8B5CF6]/30 bg-[#8B5CF6]/10 text-white">
            {mfaStatusMsg}
          </div>
        )}

        {!mfaSecret ? (
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 text-xs">
            <div>
              <p className="font-semibold text-[var(--text-primary)]">
                Protect your account with Time-based One-Time Passwords (TOTP).
              </p>
              <p className="text-[var(--text-secondary)] text-[11px] mt-0.5">
                Compatible with Google Authenticator, 1Password, Microsoft Authenticator, and Bitwarden.
              </p>
            </div>
            <button
              onClick={() => void handleStartMfaSetup()}
              disabled={mfaLoading}
              className="button-primary text-xs flex items-center gap-1.5"
            >
              {mfaLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <QrCode className="w-3.5 h-3.5" />}
              <span>Configure MFA</span>
            </button>
          </div>
        ) : (
          <form onSubmit={handleConfirmMfa} className="space-y-4 pt-2">
            <div className="p-3 bg-[var(--surface-secondary)] border border-[var(--border-color)] rounded space-y-2 text-xs">
              <span className="text-[11px] font-semibold text-[var(--text-muted)] block">
                1. Authenticator Secret Key
              </span>
              <div className="font-mono text-sm tracking-wider text-[#8B5CF6] select-all bg-black/40 p-2 rounded border border-[var(--border-color)]">
                {mfaSecret}
              </div>
              <p className="text-[11px] text-[var(--text-secondary)]">
                Or import URI directly: <span className="font-mono text-[10px] break-all text-[var(--text-muted)]">{mfaUri}</span>
              </p>
            </div>

            <div className="space-y-1.5 text-xs">
              <label className="text-[11px] font-semibold text-[var(--text-muted)]">
                2. Enter 6-digit confirmation code generated by your app:
              </label>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  maxLength={6}
                  required
                  placeholder="000000"
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, ""))}
                  className="field font-mono text-center tracking-widest max-w-[160px]"
                />
                <button type="submit" disabled={mfaLoading || mfaCode.length !== 6} className="button-primary text-xs">
                  {mfaLoading ? "Verifying..." : "Confirm & Enable"}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setMfaSecret(null);
                    setMfaUri(null);
                  }}
                  className="button-secondary text-xs"
                >
                  Cancel
                </button>
              </div>
            </div>
          </form>
        )}
      </section>

      {/* Modal: Add Notification Channel */}
      {showAddChannelModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
          <div className="card w-full max-w-md p-6 space-y-4 border border-[var(--border-color)] shadow-2xl">
            <div className="flex items-center justify-between border-b border-[var(--border-color)] pb-3">
              <h3 className="text-sm font-bold text-[var(--text-primary)]">Add SOC Notification Channel</h3>
              <button
                type="button"
                onClick={() => setShowAddChannelModal(false)}
                className="text-xs text-[var(--text-muted)] hover:text-white"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateChannel} className="space-y-3 text-xs">
              <div className="space-y-1">
                <label className="text-[11px] font-semibold text-[var(--text-muted)]">Channel Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Primary SOC Slack #alerts"
                  value={newChannelName}
                  onChange={(e) => setNewChannelName(e.target.value)}
                  className="field w-full"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[11px] font-semibold text-[var(--text-muted)]">Channel Service</label>
                <select
                  value={newChannelType}
                  onChange={(e) => setNewChannelType(e.target.value as NotificationChannel["channel_type"])}
                  className="field w-full cursor-pointer"
                >
                  <option value="slack">Slack Webhook</option>
                  <option value="teams">Microsoft Teams Webhook</option>
                  <option value="pagerduty">PagerDuty Events API v2</option>
                  <option value="opsgenie">Opsgenie Alert API</option>
                  <option value="email">Email Broadcast</option>
                </select>
              </div>

              {(newChannelType === "slack" || newChannelType === "teams") && (
                <div className="space-y-1">
                  <label className="text-[11px] font-semibold text-[var(--text-muted)]">Webhook URL</label>
                  <input
                    type="url"
                    required
                    placeholder="https://hooks.slack.com/services/..."
                    value={newWebhookUrl}
                    onChange={(e) => setNewWebhookUrl(e.target.value)}
                    className="field w-full font-mono text-[11px]"
                  />
                </div>
              )}

              {newChannelType === "pagerduty" && (
                <div className="space-y-1">
                  <label className="text-[11px] font-semibold text-[var(--text-muted)]">Routing / Integration Key</label>
                  <input
                    type="text"
                    required
                    placeholder="32-character PagerDuty service key"
                    value={newRoutingKey}
                    onChange={(e) => setNewRoutingKey(e.target.value)}
                    className="field w-full font-mono text-[11px]"
                  />
                </div>
              )}

              {newChannelType === "email" && (
                <div className="space-y-1">
                  <label className="text-[11px] font-semibold text-[var(--text-muted)]">Recipients (comma-separated)</label>
                  <input
                    type="text"
                    required
                    placeholder="soc@company.com, oncall@company.com"
                    value={newEmailRecipients}
                    onChange={(e) => setNewEmailRecipients(e.target.value)}
                    className="field w-full font-mono text-[11px]"
                  />
                </div>
              )}

              <div className="flex items-center gap-2 pt-1">
                <input
                  type="checkbox"
                  id="quietHours"
                  checked={newQuietHours}
                  onChange={(e) => setNewQuietHours(e.target.checked)}
                  className="cursor-pointer"
                />
                <label htmlFor="quietHours" className="text-[11px] text-[var(--text-secondary)] cursor-pointer">
                  Enable Quiet Hours (22:00 - 07:00 UTC, criticals will still bypass)
                </label>
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-[var(--border-color)]">
                <button
                  type="button"
                  onClick={() => setShowAddChannelModal(false)}
                  className="button-secondary text-xs"
                >
                  Cancel
                </button>
                <button type="submit" className="button-primary text-xs">
                  Save Channel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Invite / Create User */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
          <div className="card w-full max-w-md p-6 space-y-4 border border-[var(--border-color)] shadow-2xl">
            <div className="flex items-center justify-between border-b border-[var(--border-color)] pb-3">
              <h3 className="text-sm font-bold text-[var(--text-primary)]">Invite New SOC Analyst</h3>
              <button
                onClick={() => setShowCreateModal(false)}
                className="text-xs text-[var(--text-muted)] hover:text-white"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateUser} className="space-y-3 text-xs">
              <div className="space-y-1">
                <label className="text-[11px] font-semibold text-[var(--text-muted)]">Email Address</label>
                <input
                  type="email"
                  required
                  value={newEmail}
                  onChange={(e) => setNewEmail(e.target.value)}
                  className="field w-full font-mono"
                  placeholder="analyst@soc.internal"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[11px] font-semibold text-[var(--text-muted)]">Temporary Password</label>
                <input
                  type="password"
                  required
                  minLength={8}
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  className="field w-full font-mono"
                  placeholder="Minimum 8 characters"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[11px] font-semibold text-[var(--text-muted)]">Role Permission Tier</label>
                <select
                  value={newRole}
                  onChange={(e) => setNewRole(e.target.value)}
                  className="field w-full font-mono cursor-pointer"
                >
                  <option value="analyst">Analyst (Triage & Investigate)</option>
                  <option value="senior_analyst">Senior Analyst (Bulk Actions & Escalations)</option>
                  <option value="admin">Administrator (Full SOC & User Management)</option>
                  <option value="viewer">Viewer (Read-only)</option>
                </select>
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-[var(--border-color)]">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="button-secondary text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creatingUser}
                  className="button-primary text-xs flex items-center gap-1.5"
                >
                  {creatingUser ? <Loader2 className="w-3 h-3 animate-spin" /> : null}
                  <span>Create Account</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Reset Password */}
      {resetTargetUser && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
          <div className="card w-full max-w-md p-6 space-y-4 border border-[var(--border-color)] shadow-2xl">
            <div className="flex items-center justify-between border-b border-[var(--border-color)] pb-3">
              <h3 className="text-sm font-bold text-[var(--text-primary)]">
                Reset Password: {resetTargetUser.email}
              </h3>
              <button
                onClick={() => setResetTargetUser(null)}
                className="text-xs text-[var(--text-muted)] hover:text-white"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleResetPassword} className="space-y-3 text-xs">
              <p className="text-[11px] text-[var(--text-secondary)]">
                Setting a new password will immediately revoke all active sessions for this account.
              </p>

              <div className="space-y-1">
                <label className="text-[11px] font-semibold text-[var(--text-muted)]">New Password</label>
                <input
                  type="password"
                  required
                  minLength={8}
                  value={resetPasswordVal}
                  onChange={(e) => setResetPasswordVal(e.target.value)}
                  className="field w-full font-mono"
                  placeholder="Minimum 8 characters"
                />
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-[var(--border-color)]">
                <button
                  type="button"
                  onClick={() => setResetTargetUser(null)}
                  className="button-secondary text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={resettingPassword}
                  className="button-primary text-xs flex items-center gap-1.5"
                >
                  {resettingPassword ? <Loader2 className="w-3 h-3 animate-spin" /> : null}
                  <span>Reset & Revoke Sessions</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
