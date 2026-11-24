import { X } from "lucide-react";
import { useEffect } from "react";

/** Right-side slide-over panel, used for the Events detail view. */
export default function Drawer({ open, onClose, title, children }) {
  useEffect(() => {
    function handleKey(e) {
      if (e.key === "Escape") onClose();
    }
    if (open) document.addEventListener("keydown", handleKey);
    return () => document.removeEventListener("keydown", handleKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div className="absolute inset-0 bg-black/60" onClick={onClose} aria-hidden="true" />
      <div className="relative w-full max-w-md h-full bg-surface-card border-l border-surface-border shadow-2xl overflow-y-auto">
        <div className="flex items-center justify-between px-4 h-14 border-b border-surface-border sticky top-0 bg-surface-card">
          <h3 className="text-sm font-semibold text-slate-100">{title}</h3>
          <button
            onClick={onClose}
            className="p-1.5 rounded-md text-slate-500 hover:text-slate-200 hover:bg-surface-raised transition-colors"
            aria-label="Close"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="p-4">{children}</div>
      </div>
    </div>
  );
}
