import {
  AlertTriangle,
  Activity,
  FileBarChart2,
  FlaskConical,
  LayoutDashboard,
  ClipboardCheck,
  ListTree,
  Settings as SettingsIcon,
  ShieldHalf,
  UserPlus,
  Users,
} from "lucide-react";
import { NavLink } from "react-router-dom";
import { useDataMode } from "../../context/DataModeContext.jsx";
import { useBackendHealth } from "../../hooks/useBackendHealth.js";

const NAV_ITEMS = [
  { to: "/", label: "Overview", icon: LayoutDashboard, end: true },
  { to: "/live-monitoring", label: "Live Monitoring", icon: Activity },
  { to: "/events", label: "Events", icon: ListTree },
  { to: "/users", label: "Users & Baselines", icon: Users },
  { to: "/anomalies", label: "Anomalies", icon: AlertTriangle },
  { to: "/demo-lab", label: "Demo Lab", icon: FlaskConical },
  { to: "/reports", label: "Reports", icon: FileBarChart2 },
  { to: "/endpoint-requests", label: "Endpoint Requests", icon: ClipboardCheck },
  { to: "/endpoint-enrollment", label: "Endpoint Enrollment", icon: UserPlus },
  { to: "/settings", label: "Settings", icon: SettingsIcon },
];

const APP_VERSION = "0.1.0";

export default function Sidebar() {
  const { isLive } = useDataMode();
  const health = useBackendHealth();

  const systemStatus = health.loading ? "Checking..." : health.data ? "Operational" : "Unavailable";

  return (
    <aside className="w-64 shrink-0 bg-surface-raised border-r border-surface-border flex flex-col">
      <div className="flex items-center gap-2 px-4 h-16 border-b border-surface-border">
        <ShieldHalf className="h-6 w-6 text-accent" strokeWidth={1.75} />
        <div className="leading-tight">
          <p className="text-sm font-semibold text-slate-100 tracking-wide">UBADS</p>
          <p className="text-[11px] text-slate-500">Behavior Anomaly Detection</p>
        </div>
      </div>

      <nav className="flex-1 px-2 py-4 space-y-1 overflow-y-auto">
        {NAV_ITEMS.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) =>
              `flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors ${
                isActive
                  ? "bg-accent/10 text-accent border border-accent/20"
                  : "text-slate-400 border border-transparent hover:bg-surface-card hover:text-slate-200"
              }`
            }
          >
            <Icon className="h-4 w-4 shrink-0" strokeWidth={1.75} />
            <span className="truncate">{label}</span>
          </NavLink>
        ))}
      </nav>

      <div className="px-4 py-3 border-t border-surface-border space-y-1.5">
        <div className="flex items-center justify-between text-[11px]">
          <span className="text-slate-500">System status</span>
          <span className={health.data ? "text-status-ok" : "text-slate-500"}>{systemStatus}</span>
        </div>
        <div className="flex items-center justify-between text-[11px]">
          <span className="text-slate-500">Data mode</span>
          <span className={isLive ? "text-accent" : "text-status-warn"}>{isLive ? "Live" : "Demo"}</span>
        </div>
        <div className="flex items-center justify-between text-[11px]">
          <span className="text-slate-500">Version</span>
          <span className="text-slate-500">v{APP_VERSION}</span>
        </div>
      </div>
    </aside>
  );
}
