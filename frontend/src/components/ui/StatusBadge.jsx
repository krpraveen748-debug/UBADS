const VARIANTS = {
  ok: "bg-status-ok/10 text-status-ok border-status-ok/30",
  warn: "bg-status-warn/10 text-status-warn border-status-warn/30",
  danger: "bg-status-danger/10 text-status-danger border-status-danger/30",
  idle: "bg-status-idle/10 text-status-idle border-status-idle/30",
  info: "bg-accent/10 text-accent border-accent/30",
};

/**
 * status: "ok" | "warn" | "danger" | "idle" | "info"
 * A small dot + label badge used throughout the dashboard for
 * connection/collection/readiness state. Never implies a real value
 * unless the caller passes one — defaults to "idle" (unknown/not
 * connected), never "ok".
 */
export default function StatusBadge({ status = "idle", label, className = "" }) {
  const classes = VARIANTS[status] || VARIANTS.idle;
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium whitespace-nowrap ${classes} ${className}`}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current shrink-0" />
      {label}
    </span>
  );
}
