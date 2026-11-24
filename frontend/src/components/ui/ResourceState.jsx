import { Loader2, PlugZap, Wrench } from "lucide-react";
import EmptyState from "./EmptyState.jsx";

/**
 * Renders the correct state for a useApiResource() result, consistently
 * across every LIVE-mode page: loading spinner, "not available yet" (404 —
 * route not built), "backend unavailable" (network/connection failure), or
 * the caller's children once real data has arrived. Centralizing this
 * means no page can accidentally render fabricated data in place of one
 * of these states.
 */
export default function ResourceState({ resource, onReload, notAvailableHint, children }) {
  const { loading, notAvailable, unreachable, errorMessage, data } = resource;

  if (loading) {
    return (
      <div className="flex items-center justify-center gap-2 py-14 text-sm text-slate-500">
        <Loader2 className="h-4 w-4 animate-spin" />
        Loading...
      </div>
    );
  }

  if (unreachable) {
    return (
      <EmptyState
        icon={PlugZap}
        title="Backend is currently unavailable"
        description={errorMessage ? `Could not reach the backend: ${errorMessage}` : "The backend API could not be reached."}
        action={onReload ? { label: "Retry", onClick: onReload } : { label: "Go to Settings", to: "/settings" }}
      />
    );
  }

  if (notAvailable) {
    return (
      <EmptyState
        icon={Wrench}
        title="Not available yet"
        description={notAvailableHint || "This backend endpoint has not been implemented yet."}
      />
    );
  }

  return children(data);
}
