import { BellOff, CheckCheck } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { getNotifications, markAllNotificationsRead, markNotificationRead } from "../../api/portal.js";
import Card from "../../components/ui/Card.jsx";
import EmptyState from "../../components/ui/EmptyState.jsx";
import ResourceState from "../../components/ui/ResourceState.jsx";
import { useApiResource } from "../../hooks/useApiResource.js";
import { formatDate } from "./portalContent.js";

export default function NotificationsPage() {
  const navigate = useNavigate();
  const notes = useApiResource(() => getNotifications({ limit: 200 }), []);

  async function open(n) {
    if (!n.read) await markNotificationRead(n.id).catch(() => {});
    if (n.request_id) navigate(`/portal/requests/${n.request_id}`);
    else notes.reload();
  }

  async function readAll() {
    await markAllNotificationsRead().catch(() => {});
    notes.reload();
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-semibold text-slate-100">Notifications</h2>
        <button onClick={readAll} className="inline-flex items-center gap-1.5 rounded-md border border-surface-border px-3 py-1.5 text-xs text-slate-300 hover:bg-surface-raised">
          <CheckCheck className="h-3.5 w-3.5" /> Mark all as read
        </button>
      </div>
      <Card>
        <ResourceState resource={notes} onReload={notes.reload}>
          {(list) =>
            list.length === 0 ? (
              <EmptyState icon={BellOff} title="No notifications yet" description="You will be told here when an administrator approves, rejects or revokes a request." />
            ) : (
              <ul className="divide-y divide-surface-border/60">
                {list.map((n) => (
                  <li key={n.id}>
                    <button onClick={() => open(n)} className="flex w-full items-start gap-3 px-1 py-3 text-left hover:bg-surface-raised/50">
                      <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${n.read ? "bg-transparent" : "bg-accent"}`} aria-label={n.read ? "read" : "unread"} />
                      <span className="min-w-0 flex-1">
                        <span className={`block text-sm ${n.read ? "text-slate-400" : "font-semibold text-slate-100"}`}>{n.title}</span>
                        <span className="block text-xs text-slate-500">{n.message}</span>
                        <span className="block text-[11px] text-slate-600">{formatDate(n.created_at)}</span>
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            )
          }
        </ResourceState>
      </Card>
    </div>
  );
}
