import EmptyState from "./EmptyState.jsx";

/**
 * Generic table shell. `columns`: [{ key, label }]. `rows`: array of
 * objects keyed by column `key`. Renders EmptyState when rows is empty —
 * callers should pass real data only; this component never fabricates rows.
 * `onRowClick(row)` is optional — when provided, rows become clickable
 * (used by the Events page to open the detail drawer).
 */
export default function DataTable({ columns, rows, emptyTitle, emptyDescription, emptyIcon, emptyAction, onRowClick }) {
  if (!rows || rows.length === 0) {
    return <EmptyState icon={emptyIcon} title={emptyTitle} description={emptyDescription} action={emptyAction} />;
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-surface-border text-left text-xs uppercase tracking-wide text-slate-500">
            {columns.map((col) => (
              <th key={col.key} className="px-3 py-2 font-medium">
                {col.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, idx) => (
            <tr
              key={row.id ?? idx}
              onClick={onRowClick ? () => onRowClick(row) : undefined}
              className={`border-b border-surface-border/60 hover:bg-surface-raised/50 ${
                onRowClick ? "cursor-pointer" : ""
              }`}
            >
              {columns.map((col) => (
                <td key={col.key} className="px-3 py-2.5 text-slate-300">
                  {row[col.key] ?? "—"}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
