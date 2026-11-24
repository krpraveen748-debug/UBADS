import { Bell, FilePlus2, LogOut, ShieldHalf, Inbox } from "lucide-react";
import { NavLink, Navigate, Route, Routes, useNavigate } from "react-router-dom";
import { useAuth } from "../../auth/AuthContext.jsx";
import NotificationBell from "../../components/notifications/NotificationBell.jsx";
import DownloadPage from "./DownloadPage.jsx";
import NewRequest from "./NewRequest.jsx";
import NotificationsPage from "./NotificationsPage.jsx";
import PortalHome from "./PortalHome.jsx";
import RequestDetail from "./RequestDetail.jsx";

const NAV = [
  { to: "/portal", label: "My requests", icon: Inbox, end: true },
  { to: "/portal/new", label: "New request", icon: FilePlus2 },
  { to: "/portal/notifications", label: "Notifications", icon: Bell },
];

/** Everything a normal (role "user") account can see. There are no
 * administrator routes here; the backend refuses them regardless. */
export default function UserPortal() {
  const { username, logout } = useAuth();
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-surface text-slate-300">
      <header className="border-b border-surface-border bg-surface-raised/60">
        <div className="mx-auto flex max-w-5xl items-center justify-between gap-4 px-4 h-16">
          <div className="flex items-center gap-2">
            <ShieldHalf className="h-6 w-6 text-accent" strokeWidth={1.75} />
            <div className="leading-tight">
              <p className="text-sm font-semibold tracking-wide text-slate-100">UBADS</p>
              <p className="text-[11px] text-slate-500">Agent access portal</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <NotificationBell
              onOpenNotification={(n) => navigate(n.request_id ? `/portal/requests/${n.request_id}` : "/portal/notifications")}
              onViewAll={() => navigate("/portal/notifications")}
            />
            <button
              onClick={logout}
              className="inline-flex items-center gap-1.5 rounded-md border border-surface-border px-2.5 py-1 text-xs text-slate-400 hover:text-slate-200"
            >
              <LogOut className="h-3 w-3" />
              {username ? `${username} · Sign out` : "Sign out"}
            </button>
          </div>
        </div>
        <nav className="mx-auto flex max-w-5xl gap-1 px-4 pb-2" aria-label="Portal">
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                `inline-flex items-center gap-2 rounded-md border px-3 py-1.5 text-xs transition-colors ${
                  isActive
                    ? "border-accent/20 bg-accent/10 text-accent"
                    : "border-transparent text-slate-400 hover:bg-surface-card hover:text-slate-200"
                }`
              }
            >
              <Icon className="h-3.5 w-3.5" />
              {label}
            </NavLink>
          ))}
        </nav>
      </header>

      <main className="mx-auto max-w-5xl space-y-6 p-4 md:p-6">
        <Routes>
          <Route path="/portal" element={<PortalHome />} />
          <Route path="/portal/new" element={<NewRequest />} />
          <Route path="/portal/notifications" element={<NotificationsPage />} />
          <Route path="/portal/requests/:id" element={<RequestDetail />} />
          <Route path="/portal/requests/:id/download" element={<DownloadPage />} />
          <Route path="*" element={<Navigate to="/portal" replace />} />
        </Routes>
      </main>
    </div>
  );
}
