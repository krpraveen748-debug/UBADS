import { Users as UsersIcon } from "lucide-react";
import { getBaselines } from "../api/endpoints.js";
import Badge, { DemoTag } from "../components/ui/Badge.jsx";
import Card from "../components/ui/Card.jsx";
import DataModeBanner from "../components/ui/DataModeBanner.jsx";
import EmptyState from "../components/ui/EmptyState.jsx";
import ResourceState from "../components/ui/ResourceState.jsx";
import StatusBadge from "../components/ui/StatusBadge.jsx";
import { useDataMode } from "../context/DataModeContext.jsx";
import { demoUserBaseline } from "../demo/demoData.js";
import { useApiResource } from "../hooks/useApiResource.js";

function BaselineCard({ user, isDemo }) {
  const statusColor = user.baselineStatus === "Ready" ? "ok" : "warn";
  return (
    <Card>
      <div className="flex items-start justify-between mb-3">
        <div>
          <p className="text-sm font-semibold text-slate-100">User: {user.username}</p>
          <p className="text-xs text-slate-500">{user.endpoint}</p>
        </div>
        <div className="flex items-center gap-2">
          {isDemo && <DemoTag />}
          <StatusBadge status={statusColor} label={user.baselineStatus} />
        </div>
      </div>

      <div className="grid grid-cols-2 gap-y-2 text-xs">
        <span className="text-slate-500">Observed Days</span>
        <span className="text-slate-200 text-right">{user.observedDays}</span>
        <span className="text-slate-500">Events</span>
        <span className="text-slate-200 text-right">{user.events}</span>
        <span className="text-slate-500">Typical Login Window</span>
        <span className="text-slate-200 text-right">{user.typicalLoginWindow}</span>
        <span className="text-slate-500">Typical Activity Hours</span>
        <span className="text-slate-200 text-right">{user.typicalActivityHours}</span>
        <span className="text-slate-500">ML Readiness</span>
        <span className="text-slate-200 text-right">{user.mlReadiness}</span>
      </div>

      <div className="mt-3 pt-3 border-t border-surface-border/60">
        <p className="text-xs text-slate-500 mb-1.5">Common Activity Categories</p>
        <div className="flex flex-wrap gap-1.5">
          {user.commonCategories.map((c) => (
            <Badge key={c} variant="accent">
              {c}
            </Badge>
          ))}
        </div>
      </div>
    </Card>
  );
}

export default function UsersBaselines() {
  const { isLive, isDemo } = useDataMode();
  const baselines = useApiResource(getBaselines, [], { enabled: isLive });

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold text-slate-100">Users & Baselines</h2>
        <p className="text-sm text-slate-500 mt-1">
          How UBADS learns normal behavior for each real, identified user account.
        </p>
      </div>

      <DataModeBanner />

      {isDemo ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <BaselineCard user={demoUserBaseline} isDemo />
        </div>
      ) : (
        <Card>
          <ResourceState
            resource={baselines}
            onReload={baselines.reload}
            notAvailableHint="A user-baseline endpoint has not been implemented on the backend yet — ml-service/collection_status.py computes this data locally today."
          >
            {(data) => {
              const list = Array.isArray(data) ? data : [];
              if (list.length === 0) {
                return (
                  <EmptyState
                    icon={UsersIcon}
                    title="No user behavioral baseline available yet"
                    description="Baselines are built from real, multi-day activity. Collect more data, then check readiness."
                    action={{ label: "View Collection Status", to: "/reports" }}
                  />
                );
              }
              return (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {list.map((u) => (
                    <BaselineCard key={u.username} user={u} isDemo={false} />
                  ))}
                </div>
              );
            }}
          </ResourceState>
        </Card>
      )}
    </div>
  );
}
