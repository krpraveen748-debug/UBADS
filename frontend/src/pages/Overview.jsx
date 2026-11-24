import { Activity, Database, Monitor, ShieldAlert, ShieldCheck, Users as UsersIcon } from "lucide-react";
import { getAnomalies, getCollectionStatus, getEndpointStatus, getEvents, getUsers } from "../api/endpoints.js";
import BehavioralActivityChart from "../components/dashboard/BehavioralActivityChart.jsx";
import Card from "../components/ui/Card.jsx";
import DataModeBanner from "../components/ui/DataModeBanner.jsx";
import { DemoTag } from "../components/ui/Badge.jsx";
import DataTable from "../components/ui/DataTable.jsx";
import EmptyState from "../components/ui/EmptyState.jsx";
import StatCard from "../components/ui/StatCard.jsx";
import { useDataMode } from "../context/DataModeContext.jsx";
import { demoRecentEvents } from "../demo/demoData.js";
import { useApiResource } from "../hooks/useApiResource.js";

const EVENT_COLUMNS = [
  { key: "time", label: "Time" },
  { key: "user", label: "User" },
  { key: "computer", label: "Computer" },
  { key: "event", label: "Event" },
  { key: "category", label: "Category" },
  { key: "status", label: "Status" },
];

/** value/hint for a StatCard driven by a useApiResource() result — never
 * renders a number that didn't come from a real backend response. */
function metricFrom(resource, formatValue) {
  if (resource.loading) return { value: "…", hint: "Loading..." };
  if (resource.notAvailable) return { value: "--", hint: "Not available yet" };
  if (resource.unreachable) return { value: "--", hint: "Backend unavailable" };
  return { value: formatValue(resource.data), hint: "Live" };
}

export default function Overview() {
  const { isLive, isDemo } = useDataMode();

  const events = useApiResource(getEvents, [], { enabled: isLive });
  const users = useApiResource(getUsers, [], { enabled: isLive });
  const anomalies = useApiResource(getAnomalies, [], { enabled: isLive });
  const collectionStatus = useApiResource(getCollectionStatus, [], { enabled: isLive });
  const endpointStatus = useApiResource(getEndpointStatus, [], { enabled: isLive });

  const endpointsMetric = metricFrom(endpointStatus, (d) => `${d?.online ?? 0} Online`);
  const eventsMetric = metricFrom(events, (d) => (Array.isArray(d) ? d.length : (d?.total ?? "--")));
  const usersMetric = metricFrom(users, (d) => (Array.isArray(d) ? d.length : (d?.total ?? "--")));
  const anomaliesMetric = metricFrom(anomalies, (d) => (Array.isArray(d) ? d.length : (d?.total ?? "--")));
  const readinessMetric = metricFrom(collectionStatus, (d) => d?.decision || "--");
  const lastEventMetric = metricFrom(events, (d) => {
    const list = Array.isArray(d) ? d : [];
    return list[0]?.timestamp || "--";
  });

  const demoMetrics = [
    { icon: Monitor, label: "Endpoints", value: "1 Online", hint: "DEMO" },
    { icon: Database, label: "Events Collected", value: demoRecentEvents.length, hint: "DEMO" },
    { icon: UsersIcon, label: "Active Users", value: 1, hint: "DEMO" },
    { icon: ShieldAlert, label: "Anomalies", value: 3, hint: "DEMO" },
    { icon: ShieldCheck, label: "ML Readiness", value: "Illustrative", hint: "DEMO" },
    { icon: Activity, label: "Last Event", value: "08:41", hint: "DEMO" },
  ];

  const liveMetrics = [
    { icon: Monitor, label: "Endpoints", ...endpointsMetric },
    { icon: Database, label: "Events Collected", ...eventsMetric },
    { icon: UsersIcon, label: "Active Users", ...usersMetric },
    { icon: ShieldAlert, label: "Anomalies", ...anomaliesMetric },
    { icon: ShieldCheck, label: "ML Readiness", ...readinessMetric },
    { icon: Activity, label: "Last Event", ...lastEventMetric },
  ];

  const metrics = isDemo ? demoMetrics : liveMetrics;
  const activityRows = isDemo ? demoRecentEvents : Array.isArray(events.data) ? events.data : [];

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-slate-100">Security Overview</h2>
        <p className="text-sm text-slate-500 mt-1">
          Monitor endpoint behavior, user baselines, and detected anomalies.
        </p>
      </div>

      <DataModeBanner />

      <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        {metrics.map((m) => (
          <StatCard key={m.label} icon={m.icon} label={m.label} value={m.value} hint={m.hint} />
        ))}
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <Card
          title="Recent Security Activity"
          className="xl:col-span-2"
          action={isDemo ? <DemoTag /> : null}
        >
          {activityRows.length > 0 ? (
            <DataTable columns={EVENT_COLUMNS} rows={activityRows} />
          ) : isDemo ? (
            <EmptyState title="No demo events configured" />
          ) : (
            <EmptyState
              icon={Database}
              title="No live events available"
              description="Connect an endpoint/backend to display real activity."
              action={{ label: "Go to Endpoint Enrollment", to: "/endpoint-enrollment" }}
            />
          )}
        </Card>

        <Card title="Data Source">
          <div className="space-y-3 text-xs text-slate-400">
            <p>
              UBADS is designed around real Windows telemetry: an authorized endpoint runs the collector, which
              writes normalized events to local storage, which feeds feature engineering and (eventually) anomaly
              detection.
            </p>
            <p>
              Use the <span className="text-accent font-medium">Demo Lab</span> to see how detection results would
              be explained, without waiting for real anomalies to occur naturally.
            </p>
          </div>
        </Card>
      </div>

      <BehavioralActivityChart eventsResource={events} />
    </div>
  );
}
