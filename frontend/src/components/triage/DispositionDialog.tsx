"use client";

import { useEffect, useRef, useState } from "react";
import { Loader2, X } from "lucide-react";
import {
  ACTION_LABELS,
  VERDICT_HELP,
  VERDICT_LABELS,
  roleBlock,
  type DispositionAction,
  type Verdict,
} from "@/lib/triage";

type Props = {
  action: DispositionAction;
  /** Number of alerts the action applies to (1 for the detail page). */
  count: number;
  /** Severity and status of the single target, used to explain role limits; omitted for bulk. */
  severity?: string;
  status?: string;
  role?: string;
  onCancel: () => void;
  onConfirm: (input: { note: string; verdict?: Verdict }) => Promise<void>;
};

const ACTION_HELP: Record<DispositionAction, string> = {
  close: "Resolve the alert with a verdict. The verdict feeds rule precision on the dashboard.",
  escalate: "Hand off to incident response. The alert stays open until closed.",
  suppress: "Hide this alert as noise without a full verdict.",
  reopen: "Return the alert to the open queue.",
};

export default function DispositionDialog({ action, count, severity, status, role, onCancel, onConfirm }: Props) {
  const [verdict, setVerdict] = useState<Verdict | undefined>();
  const [note, setNote] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const noteRef = useRef<HTMLTextAreaElement | null>(null);

  useEffect(() => {
    noteRef.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onCancel();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onCancel]);

  const needsVerdict = action === "close";
  const blocked = severity ? roleBlock(role, severity, action, verdict, status) : null;
  const canSubmit = !saving && note.trim().length > 0 && (!needsVerdict || !!verdict) && !blocked;

  const submit = async () => {
    if (!canSubmit) return;
    setSaving(true);
    setError(null);
    try {
      await onConfirm({ note: note.trim(), verdict: needsVerdict || action === "suppress" ? verdict : undefined });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Action failed");
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 p-4" role="dialog" aria-modal="true" aria-labelledby="disposition-title">
      <div className="card w-full max-w-lg p-5 space-y-4 bg-[var(--card-bg)]">
        <div className="flex items-start justify-between gap-3">
          <div>
            <h2 id="disposition-title" className="text-sm font-bold text-[var(--text-primary)]">
              {ACTION_LABELS[action]} {count === 1 ? "alert" : `${count} alerts`}
            </h2>
            <p className="text-xs text-[var(--text-muted)] mt-0.5">{ACTION_HELP[action]}</p>
          </div>
          <button onClick={onCancel} className="p-1 rounded hover:bg-[var(--surface-hover)]" aria-label="Cancel">
            <X className="w-4 h-4" />
          </button>
        </div>

        {(needsVerdict || action === "suppress") && (
          <fieldset className="space-y-2">
            <legend className="text-[11px] font-semibold text-[var(--text-muted)] mb-1">
              Verdict {needsVerdict ? "(required)" : "(optional)"}
            </legend>
            {(Object.keys(VERDICT_LABELS) as Verdict[]).map((v) => (
              <label
                key={v}
                className={`flex items-start gap-2.5 p-2.5 rounded border cursor-pointer text-xs ${
                  verdict === v ? "border-[var(--text-primary)] bg-[var(--surface-hover)]" : "border-[var(--border-color)]"
                }`}
              >
                <input type="radio" name="verdict" value={v} checked={verdict === v} onChange={() => setVerdict(v)} className="mt-0.5" aria-label={VERDICT_LABELS[v]} />
                <span>
                  <span className="font-semibold text-[var(--text-primary)] block">{VERDICT_LABELS[v]}</span>
                  <span className="text-[var(--text-muted)]">{VERDICT_HELP[v]}</span>
                </span>
              </label>
            ))}
          </fieldset>
        )}

        <div className="space-y-1">
          <label htmlFor="disposition-note" className="text-[11px] font-semibold text-[var(--text-muted)]">
            Note (required): what you checked and why
          </label>
          <textarea
            id="disposition-note"
            ref={noteRef}
            value={note}
            onChange={(e) => setNote(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) void submit();
            }}
            rows={4}
            maxLength={5000}
            className="field w-full text-xs p-2.5"
            placeholder="e.g. Confirmed with IT: scheduled backup script on this host."
          />
        </div>

        {blocked && <p className="text-xs text-[#F59E0B]">{blocked}</p>}
        {error && <p className="text-xs text-[#EF4444]">{error}</p>}

        <div className="flex justify-end gap-2">
          <button onClick={onCancel} className="button-secondary text-xs">Cancel</button>
          <button onClick={() => void submit()} disabled={!canSubmit} className="button-primary text-xs disabled:opacity-50">
            {saving && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
            <span>{ACTION_LABELS[action]}</span>
            <kbd className="text-[10px] opacity-60 ml-1">Ctrl+Enter</kbd>
          </button>
        </div>
      </div>
    </div>
  );
}
