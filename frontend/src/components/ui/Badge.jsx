const VARIANTS = {
  slate: "bg-slate-500/10 text-slate-300 border-slate-500/30",
  accent: "bg-accent/10 text-accent border-accent/30",
  ok: "bg-status-ok/10 text-status-ok border-status-ok/30",
  warn: "bg-status-warn/10 text-status-warn border-status-warn/30",
  danger: "bg-status-danger/10 text-status-danger border-status-danger/30",
};

/** Compact, non-dotted label badge (unlike StatusBadge, no status dot) —
 * used for category tags, "DEMO DATA" / "SIMULATED RESULT" markers, and
 * risk levels. */
export default function Badge({ children, variant = "slate", className = "" }) {
  return (
    <span
      className={`inline-flex items-center rounded border px-2 py-0.5 text-[11px] font-medium tracking-wide whitespace-nowrap ${VARIANTS[variant] || VARIANTS.slate} ${className}`}
    >
      {children}
    </span>
  );
}

const RISK_VARIANT = { High: "danger", Medium: "warn", Low: "ok" };

export function RiskBadge({ risk }) {
  return <Badge variant={RISK_VARIANT[risk] || "slate"}>{risk?.toUpperCase() || "UNKNOWN"}</Badge>;
}

export function DemoTag({ children = "DEMO DATA" }) {
  return (
    <Badge variant="warn" className="uppercase">
      {children}
    </Badge>
  );
}
