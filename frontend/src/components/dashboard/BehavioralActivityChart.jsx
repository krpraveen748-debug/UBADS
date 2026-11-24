import { Activity } from "lucide-react";
import { useState } from "react";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { demoHourlyActivity } from "../../demo/demoData.js";
import { useDataMode } from "../../context/DataModeContext.jsx";
import Card from "../ui/Card.jsx";
import { DemoTag } from "../ui/Badge.jsx";
import EmptyState from "../ui/EmptyState.jsx";
import ResourceState from "../ui/ResourceState.jsx";

const FILTERS = ["Today", "Last 24 Hours", "Last 7 Days", "Last 30 Days"];

/**
 * `eventsResource`: a useApiResource() result for real hourly event data
 * (LIVE mode only — this component never fabricates that data itself).
 */
export default function BehavioralActivityChart({ eventsResource }) {
  const { isDemo } = useDataMode();
  const [filter, setFilter] = useState("Today");

  return (
    <Card
      title="Behavioral Activity"
      action={
        <div className="flex items-center gap-2">
          {isDemo && <DemoTag />}
          <div className="hidden md:flex items-center gap-1 rounded-md border border-surface-border p-0.5">
            {FILTERS.map((f) => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`px-2 py-1 text-[11px] rounded transition-colors ${
                  filter === f ? "bg-accent/10 text-accent" : "text-slate-500 hover:text-slate-300"
                }`}
              >
                {f}
              </button>
            ))}
          </div>
        </div>
      }
    >
      {isDemo ? (
        filter === "Today" ? (
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={demoHourlyActivity}>
                <CartesianGrid strokeDasharray="3 3" stroke="#232c3a" vertical={false} />
                <XAxis dataKey="hour" tick={{ fill: "#64748b", fontSize: 10 }} interval={2} axisLine={{ stroke: "#232c3a" }} tickLine={false} />
                <YAxis tick={{ fill: "#64748b", fontSize: 10 }} axisLine={false} tickLine={false} width={28} />
                <Tooltip
                  contentStyle={{ background: "#151c28", border: "1px solid #232c3a", borderRadius: 8, fontSize: 12 }}
                  labelStyle={{ color: "#cbd5e1" }}
                  cursor={{ fill: "rgba(34,211,238,0.06)" }}
                />
                <Bar dataKey="events" fill="#22d3ee" radius={[3, 3, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        ) : (
          <EmptyState
            icon={Activity}
            title="No demo dataset for this range"
            description="This simulation only includes an illustrative single-day activity curve. Select 'Today' to view it."
          />
        )
      ) : (
        <ResourceState
          resource={eventsResource}
          notAvailableHint="Behavioral event history is not exposed by the backend yet."
        >
          {(data) =>
            data && data.length > 0 ? (
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={data}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#232c3a" vertical={false} />
                    <XAxis dataKey="hour" tick={{ fill: "#64748b", fontSize: 10 }} axisLine={{ stroke: "#232c3a" }} tickLine={false} />
                    <YAxis tick={{ fill: "#64748b", fontSize: 10 }} axisLine={false} tickLine={false} width={28} />
                    <Tooltip contentStyle={{ background: "#151c28", border: "1px solid #232c3a", borderRadius: 8 }} />
                    <Bar dataKey="events" fill="#22d3ee" radius={[3, 3, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <EmptyState
                icon={Activity}
                title="Insufficient real data to chart yet"
                description="Behavioral activity will appear here once enough real endpoint events have been collected. No synthetic data is substituted."
                action={{ label: "View Collection Status", to: "/reports" }}
              />
            )
          }
        </ResourceState>
      )}
    </Card>
  );
}
