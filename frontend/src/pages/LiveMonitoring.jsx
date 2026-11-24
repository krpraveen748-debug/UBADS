import { Activity, RadioTower } from "lucide-react";
import { getEndpointStatus } from "../api/endpoints.js";
import Card from "../components/ui/Card.jsx";
import DataModeBanner from "../components/ui/DataModeBanner.jsx";
import EmptyState from "../components/ui/EmptyState.jsx";
import ResourceState from "../components/ui/ResourceState.jsx";
import StatusBadge from "../components/ui/StatusBadge.jsx";
import { useDataMode } from "../context/DataModeContext.jsx";
import { useApiResource } from "../hooks/useApiResource.js";

const CATEGORIES = ["Authentication", "Process", "File", "Device"];

function Field({ label, value }) {
  return (
    <div className="flex items-center justify-between py-2 border-b border-surface-border/60 last:border-0">
      <span className="text-xs text-slate-500">{label}</span>
      <span className="text-sm text-slate-200">{value}</span>
    </div>
  );
}

export default function LiveMonitoring() {
  const { isLive } = useDataMode();
  const endpointStatus = useApiResource(getEndpointStatus, [], { enabled: isLive });

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold text-slate-100">Live Monitoring</h2>
        <p className="text-sm text-slate-500 mt-1">Real-time collector and endpoint status.</p>
      </div>

      <DataModeBanner description="Live Monitoring only ever reflects a real backend/collector connection — it never simulates endpoint status." />

      {!isLive ? (
        <Card>
          <EmptyState
            icon={RadioTower}
            title="Live Monitoring is a LIVE-mode page"
            description="Switch to Live Data mode to view real collector/endpoint status. This page does not simulate monitoring data."
          />
        </Card>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <Card title="Endpoint Status">
            <ResourceState
              resource={endpointStatus}
              onReload={endpointStatus.reload}
              notAvailableHint="The backend does not yet expose an endpoint status route."
            >
              {(data) => (
                <div>
                  <Field label="Endpoint" value={data.endpointName || "—"} />
                  <Field
                    label="Status"
                    value={<StatusBadge status={data.online ? "ok" : "danger"} label={data.online ? "Online" : "Offline"} />}
                  />
                  <Field
                    label="Collector"
                    value={
                      <StatusBadge status={data.collectorRunning ? "ok" : "danger"} label={data.collectorRunning ? "Running" : "Stopped"} />
                    }
                  />
                  <Field label="Last Heartbeat" value={data.lastHeartbeat || "—"} />
                  <Field label="Last Event" value={data.lastEvent || "—"} />
                  <Field label="Events / Minute" value={data.eventsPerMinute ?? "—"} />
                  <Field label="Current User" value={data.currentUser || "—"} />
                </div>
              )}
            </ResourceState>
          </Card>

          <Card title="Collection Categories">
            <p className="text-xs text-slate-500 mb-3">
              Categories this endpoint is configured to collect (see log-collector's --categories).
            </p>
            <ResourceState resource={endpointStatus} notAvailableHint="Category configuration is not exposed by the backend yet.">
              {(data) => (
                <div className="flex flex-wrap gap-2">
                  {(data.categories || CATEGORIES).map((c) => (
                    <span
                      key={c}
                      className="inline-flex items-center gap-1.5 rounded-md border border-surface-border bg-surface-raised px-2.5 py-1.5 text-xs text-slate-300"
                    >
                      <Activity className="h-3 w-3 text-accent" />
                      {c}
                    </span>
                  ))}
                </div>
              )}
            </ResourceState>
          </Card>
        </div>
      )}
    </div>
  );
}
