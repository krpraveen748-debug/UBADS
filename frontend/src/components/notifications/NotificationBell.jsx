import { Bell, CheckCheck } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { getNotifications, getUnreadCount, markAllNotificationsRead, markNotificationRead } from "../../api/portal.js";
import { formatDate } from "../../pages/portal/portalContent.js";

const POLL_MS = 30_000;

/**
 * Bell with an unread badge and a dropdown of recent notifications.
 * `onOpenNotification(notification)` navigates to the related request (the
 * portal and the admin dashboard link to different pages). Everything shown
 * is the signed-in account's OWN notifications - the backend enforces that.
 */
export default function NotificationBell({ onOpenNotification, onViewAll }) {
  const [unread, setUnread] = useState(0);
  const [open, setOpen] = useState(false);
  const [items, setItems] = useState(null);
  const [error, setError] = useState(false);
  const box = useRef(null);

  const refreshCount = useCallback(() => {
    getUnreadCount().then(setUnread).catch(() => {});
  }, []);

  const loadList = useCallback(() => {
    setError(false);
    getNotifications({ limit: 20 })
      .then(setItems)
      .catch(() => setError(true));
  }, []);

  useEffect(() => {
    refreshCount();
    const t = setInterval(refreshCount, POLL_MS);
    return () => clearInterval(t);
  }, [refreshCount]);

  useEffect(() => {
    if (!open) return undefined;
    loadList();
    const onClick = (e) => {
      if (box.current && !box.current.contains(e.target)) setOpen(false);
    };
    const onKey = (e) => e.key === "Escape" && setOpen(false);
    document.addEventListener("mousedown", onClick);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onClick);
      document.removeEventListener("keydown", onKey);
    };
  }, [open, loadList]);

  async function openOne(n) {
    try {
      if (!n.read) await markNotificationRead(n.id);
    } catch {
      // still navigate; the count refreshes below
    }
    setOpen(false);
    refreshCount();
    onOpenNotification?.(n);
  }

  async function readAll() {
    try {
      await markAllNotificationsRead();
    } finally {
      loadList();
      refreshCount();
    }
  }

  return (
    <div className="relative" ref={box}>
      <button
        onClick={() => setOpen((o) => !o)}
        aria-label={unread ? `Notifications, ${unread} unread` : "Notifications"}
        aria-expanded={open}
        className="relative rounded-md border border-surface-border p-1.5 text-slate-400 hover:text-slate-200"
      >
        <Bell className="h-4 w-4" />
        {unread > 0 && (
          <span
            data-testid="unread-badge"
            className="absolute -top-1.5 -right-1.5 min-w-[1.1rem] rounded-full bg-status-danger px-1 text-center text-[10px] font-semibold leading-4 text-white"
          >
            {unread > 99 ? "99+" : unread}
          </span>
        )}
      </button>

      {open && (
        <div role="menu" aria-label="Notifications" className="absolute right-0 z-50 mt-2 w-80 rounded-lg border border-surface-border bg-surface-card shadow-2xl">
          <div className="flex items-center justify-between border-b border-surface-border px-3 py-2">
            <span className="text-xs font-semibold text-slate-200">Notifications</span>
            <button
              onClick={readAll}
              disabled={!unread}
              className="inline-flex items-center gap-1 text-[11px] text-accent disabled:text-slate-600"
            >
              <CheckCheck className="h-3 w-3" /> Mark all read
            </button>
          </div>
          <div className="max-h-80 overflow-y-auto">
            {error && <p role="alert" className="p-3 text-xs text-status-danger">Could not load notifications.</p>}
            {!error && items === null && <p className="p-3 text-xs text-slate-500">Loading...</p>}
            {!error && items?.length === 0 && <p className="p-3 text-xs text-slate-500">No notifications yet.</p>}
            {items?.map((n) => (
              <button
                key={n.id}
                role="menuitem"
                onClick={() => openOne(n)}
                className={`block w-full border-b border-surface-border/60 px-3 py-2 text-left hover:bg-surface-raised ${n.read ? "" : "bg-accent/5"}`}
              >
                <span className="flex items-center gap-2">
                  {!n.read && <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-accent" aria-label="unread" />}
                  <span className={`text-xs ${n.read ? "text-slate-400" : "font-semibold text-slate-100"}`}>{n.title}</span>
                </span>
                <span className="mt-0.5 block text-[11px] text-slate-500">{n.message}</span>
                <span className="mt-0.5 block text-[10px] text-slate-600">{formatDate(n.created_at)}</span>
              </button>
            ))}
          </div>
          {onViewAll && (
            <button onClick={() => { setOpen(false); onViewAll(); }} className="block w-full px-3 py-2 text-center text-[11px] text-accent hover:bg-surface-raised">
              View all
            </button>
          )}
        </div>
      )}
    </div>
  );
}
