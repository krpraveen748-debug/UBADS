export default function Card({ title, action, children, className = "" }) {
  return (
    <div className={`bg-surface-card border border-surface-border rounded-lg ${className}`}>
      {(title || action) && (
        <div className="flex items-center justify-between px-4 py-3 border-b border-surface-border">
          {title && <h3 className="text-sm font-medium text-slate-200">{title}</h3>}
          {action}
        </div>
      )}
      <div className="p-4">{children}</div>
    </div>
  );
}
