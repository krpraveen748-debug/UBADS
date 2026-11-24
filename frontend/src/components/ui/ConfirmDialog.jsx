import { Loader2 } from "lucide-react";
import { useEffect, useState } from "react";

/**
 * Modal confirmation. Optional free-text reason (`reasonLabel`); when
 * `reasonRequired` the confirm button stays disabled until it is non-blank.
 * `onConfirm(reason)` may return a promise; a thrown error is shown inline
 * and the dialog stays open so nothing is lost.
 */
export default function ConfirmDialog({
  open,
  title,
  message,
  confirmLabel = "Confirm",
  tone = "default",
  reasonLabel,
  reasonRequired = false,
  confirmDisabled = false,
  onConfirm,
  onCancel,
  children,
}) {
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (open) {
      setReason("");
      setError(null);
      setBusy(false);
    }
  }, [open]);

  useEffect(() => {
    function onKey(e) {
      if (e.key === "Escape" && !busy) onCancel();
    }
    if (open) document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, busy, onCancel]);

  if (!open) return null;

  const blocked = busy || confirmDisabled || (reasonRequired && reason.trim().length < 3);
  const confirmClasses =
    tone === "danger"
      ? "bg-status-danger/10 border-status-danger/40 text-status-danger hover:bg-status-danger/20"
      : "bg-accent/10 border-accent/30 text-accent hover:bg-accent/20";

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      await onConfirm(reason.trim());
    } catch (err) {
      setError(err?.response?.data?.detail || err?.message || "The action failed.");
      setBusy(false);
    }
  }

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-label={title}>
      <div className="absolute inset-0 bg-black/70" onClick={busy ? undefined : onCancel} aria-hidden="true" />
      <div className="relative w-full max-w-md rounded-lg border border-surface-border bg-surface-card shadow-2xl">
        <div className="px-4 py-3 border-b border-surface-border">
          <h3 className="text-sm font-semibold text-slate-100">{title}</h3>
        </div>
        <div className="p-4 space-y-3">
          {message && <p className="text-sm text-slate-300">{message}</p>}
          {children}
          {reasonLabel && (
            <label className="block text-xs text-slate-400">
              {reasonLabel}
              {reasonRequired && <span className="text-status-danger"> *</span>}
              <textarea
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                rows={3}
                maxLength={500}
                className="mt-1 w-full bg-surface border border-surface-border rounded-md px-3 py-2 text-sm text-slate-200 focus:outline-none focus:ring-1 focus:ring-accent/50"
              />
            </label>
          )}
          {error && (
            <p role="alert" className="text-xs text-status-danger">
              {error}
            </p>
          )}
        </div>
        <div className="flex justify-end gap-2 px-4 py-3 border-t border-surface-border">
          <button
            onClick={onCancel}
            disabled={busy}
            className="rounded-md border border-surface-border px-3 py-1.5 text-xs text-slate-300 hover:bg-surface-raised disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            onClick={submit}
            disabled={blocked}
            className={`inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs font-medium disabled:opacity-50 ${confirmClasses}`}
          >
            {busy && <Loader2 className="h-3 w-3 animate-spin" />}
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
