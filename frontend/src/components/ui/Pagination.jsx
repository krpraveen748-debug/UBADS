import { ChevronLeft, ChevronRight } from "lucide-react";

export default function Pagination({ page, pageCount, onPageChange, totalLabel }) {
  if (pageCount <= 0) return null;

  return (
    <div className="flex items-center justify-between border-t border-surface-border pt-3 mt-3">
      <p className="text-xs text-slate-500">{totalLabel}</p>
      <div className="flex items-center gap-2">
        <button
          onClick={() => onPageChange(Math.max(1, page - 1))}
          disabled={page <= 1}
          className="p-1.5 rounded-md border border-surface-border text-slate-400 hover:text-slate-200 hover:bg-surface-raised disabled:opacity-40 disabled:hover:bg-transparent transition-colors"
          aria-label="Previous page"
        >
          <ChevronLeft className="h-4 w-4" />
        </button>
        <span className="text-xs text-slate-400 tabular-nums">
          Page {page} of {pageCount}
        </span>
        <button
          onClick={() => onPageChange(Math.min(pageCount, page + 1))}
          disabled={page >= pageCount}
          className="p-1.5 rounded-md border border-surface-border text-slate-400 hover:text-slate-200 hover:bg-surface-raised disabled:opacity-40 disabled:hover:bg-transparent transition-colors"
          aria-label="Next page"
        >
          <ChevronRight className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
}
