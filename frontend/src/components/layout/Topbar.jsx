import { FlaskConical, LogOut, Radio } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../../auth/AuthContext.jsx";
import NotificationBell from "../notifications/NotificationBell.jsx";
import { useDataMode } from "../../context/DataModeContext.jsx";
import { useBackendHealth } from "../../hooks/useBackendHealth.js";
import StatusBadge from "../ui/StatusBadge.jsx";

export default function Topbar({ title, subtitle }) {
  const { isLive, toggleMode } = useDataMode();
  const health = useBackendHealth();
  const { username, logout } = useAuth();
  const navigate = useNavigate();

  const backendStatus = health.loading ? "idle" : health.data ? "ok" : "danger";
  const backendLabel = health.loading ? "Checking backend..." : health.data ? "Backend Connected" : "Backend Unavailable";

  return (
    <header className="h-16 border-b border-surface-border bg-surface-raised/60 flex items-center justify-between px-6 gap-4">
      <div className="min-w-0">
        <h1 className="text-base font-semibold text-slate-100 truncate">{title}</h1>
        {subtitle && <p className="text-xs text-slate-500 truncate">{subtitle}</p>}
      </div>

      <div className="flex items-center gap-2 shrink-0">
        <button
          onClick={toggleMode}
          title="Switch data mode"
          className="transition-transform hover:scale-[1.03] active:scale-95"
        >
          <StatusBadge
            status={isLive ? "info" : "warn"}
            label={
              <span className="inline-flex items-center gap-1">
                {isLive ? <Radio className="h-3 w-3" /> : <FlaskConical className="h-3 w-3" />}
                {isLive ? "LIVE DATA" : "DEMO MODE"}
              </span>
            }
          />
        </button>

        {isLive ? (
          <>
            <StatusBadge status={backendStatus} label={backendLabel} />
            <StatusBadge status="idle" label="Endpoint status unknown" />
          </>
        ) : (
          <StatusBadge status="warn" label="No real endpoint data affected" />
        )}
        <NotificationBell
          onOpenNotification={(n) => navigate(n.request_id ? `/endpoint-requests?request=${n.request_id}` : "/endpoint-requests")}
        />
        <button
          onClick={logout}
          title="Sign out"
          className="inline-flex items-center gap-1.5 rounded-md border border-surface-border px-2.5 py-1 text-xs text-slate-400 hover:text-slate-200"
        >
          <LogOut className="h-3 w-3" />
          {username ? `${username} · Sign out` : "Sign out"}
        </button>
      </div>
    </header>
  );
}
