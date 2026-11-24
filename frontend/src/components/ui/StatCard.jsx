export default function StatCard({ icon: Icon, label, value, hint }) {
  return (
    <div className="bg-surface-card border border-surface-border rounded-lg p-4">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
          <p className="mt-1 text-2xl font-semibold text-slate-100">{value}</p>
          {hint && <p className="mt-1 text-xs text-slate-500">{hint}</p>}
        </div>
        {Icon && (
          <div className="rounded-md bg-surface-raised p-2 border border-surface-border">
            <Icon className="h-4 w-4 text-accent" strokeWidth={1.75} />
          </div>
        )}
      </div>
    </div>
  );
}
