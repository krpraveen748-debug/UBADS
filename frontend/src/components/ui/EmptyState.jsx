import { Link } from "react-router-dom";

/**
 * `action`: optional { label, to } (internal link) or { label, onClick }.
 * Used throughout the app so empty/unavailable states explain WHY and give
 * the user something to do next, rather than a bare "No data".
 */
export default function EmptyState({ icon: Icon, title, description, action }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-14 text-center px-4">
      {Icon && (
        <div className="rounded-full bg-surface-raised p-3 border border-surface-border">
          <Icon className="h-6 w-6 text-slate-500" strokeWidth={1.5} />
        </div>
      )}
      <div>
        <p className="text-sm font-medium text-slate-300">{title}</p>
        {description && <p className="mt-1 text-xs text-slate-500 max-w-sm">{description}</p>}
      </div>
      {action &&
        (action.to ? (
          <Link
            to={action.to}
            className="mt-1 rounded-md bg-accent/10 border border-accent/30 text-accent text-xs font-medium px-3 py-1.5 hover:bg-accent/20 transition-colors"
          >
            {action.label}
          </Link>
        ) : (
          <button
            onClick={action.onClick}
            className="mt-1 rounded-md bg-accent/10 border border-accent/30 text-accent text-xs font-medium px-3 py-1.5 hover:bg-accent/20 transition-colors"
          >
            {action.label}
          </button>
        ))}
    </div>
  );
}
