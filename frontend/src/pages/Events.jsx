import { ListTree, Search } from "lucide-react";
import { useMemo, useState } from "react";
import { getEndpoints, getEvents } from "../api/endpoints.js";
import { DemoTag } from "../components/ui/Badge.jsx";
import Card from "../components/ui/Card.jsx";
import DataModeBanner from "../components/ui/DataModeBanner.jsx";
import DataTable from "../components/ui/DataTable.jsx";
import Drawer from "../components/ui/Drawer.jsx";
import Pagination from "../components/ui/Pagination.jsx";
import ResourceState from "../components/ui/ResourceState.jsx";
import { useDataMode } from "../context/DataModeContext.jsx";
import { demoRecentEvents } from "../demo/demoData.js";
import { useApiResource } from "../hooks/useApiResource.js";

const COLUMNS = [
  { key: "timestamp", label: "Timestamp" },
  { key: "username", label: "Username" },
  { key: "endpoint", label: "Endpoint" },
  { key: "category", label: "Category" },
  { key: "event_id", label: "Event ID" },
  { key: "source", label: "Source" },
  { key: "account_type", label: "Account Type" },
];

const CATEGORY_EVENT_IDS = {
  Authentication: 4624,
  Process: 4688,
  File: 4663,
  Device: 6416,
};

const PAGE_SIZE = 5;

/** Normalize either a real backend row or a demo row into one shared shape
 * this page's table/filters/drawer operate on. */
function toDisplayRow(raw, { isDemo }) {
  if (isDemo) {
    return {
      id: raw.id,
      timestamp: raw.time,
      username: raw.user,
      endpoint: raw.computer,
      category: raw.category,
      event_id: CATEGORY_EVENT_IDS[raw.category] ?? "—",
      source: raw.source,
      account_type: "human_or_unknown",
      _eventLabel: raw.event,
      _status: raw.status,
    };
  }
  return {
    id: raw.id ?? raw.event_uid,
    timestamp: raw.timestamp_utc ?? raw.timestamp,
    username: raw.username,
    endpoint: raw.computer_name,
    // The real, credentialed enrolled-endpoint identity (Phase 14) — NOT
    // the same thing as `endpoint` (a self-reported Windows computer
    // name). Two endpoints could in principle report the same computer
    // name; endpoint_id is what actually tells them apart. Demo rows have
    // no real enrolled endpoint at all.
    endpoint_id: isDemo ? null : (raw.endpoint_id ?? null),
    category: raw.event_category,
    event_id: raw.event_id,
    source: raw.log_name,
    account_type: raw.account_type,
    _eventLabel: raw.event_type,
    _status: null,
  };
}

export default function Events() {
  const { isDemo } = useDataMode();

  const [search, setSearch] = useState("");
  const [category, setCategory] = useState("All");
  const [username, setUsername] = useState("All");
  const [endpoint, setEndpoint] = useState("All");
  const [endpointId, setEndpointId] = useState("All");
  // Endpoint scoping happens on the SERVER (endpoint_id query param), so a
  // busy endpoint can never push another endpoint's events out of the page.
  const events = useApiResource(
    () => getEvents({ limit: 500, ...(endpointId !== "All" ? { endpoint_id: endpointId } : {}) }),
    [endpointId],
    { enabled: !isDemo }
  );
  const enrolledEndpoints = useApiResource(getEndpoints, [], { enabled: !isDemo });
  const [eventId, setEventId] = useState("All");
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState(null);

  const sourceRows = isDemo ? demoRecentEvents : Array.isArray(events.data) ? events.data : [];
  const rows = useMemo(() => sourceRows.map((r) => toDisplayRow(r, { isDemo })), [sourceRows, isDemo]);

  const categories = useMemo(() => ["All", ...new Set(rows.map((r) => r.category).filter(Boolean))], [rows]);
  const usernames = useMemo(() => ["All", ...new Set(rows.map((r) => r.username).filter(Boolean))], [rows]);
  const endpoints = useMemo(() => ["All", ...new Set(rows.map((r) => r.endpoint).filter(Boolean))], [rows]);
  const eventIds = useMemo(() => ["All", ...new Set(rows.map((r) => r.event_id).filter(Boolean))], [rows]);

  // Real ENROLLED endpoints (with a display name), for the credentialed
  // per-endpoint filter — sourced from GET /api/endpoints, not derived
  // from the events themselves, so an enrolled endpoint with zero events
  // yet still shows up (and, more importantly, so filtering is by the
  // real endpoint_id, never by a spoofable/duplicable computer name).
  const enrolledEndpointOptions = useMemo(() => {
    const list = Array.isArray(enrolledEndpoints.data) ? enrolledEndpoints.data : [];
    return [
      { value: "All", label: "All" },
      ...list.map((e) => ({
        value: e.endpoint_id,
        label: e.display_name ? `${e.display_name} (${e.endpoint_id.slice(0, 8)})` : e.endpoint_id,
      })),
    ];
  }, [enrolledEndpoints.data]);

  const filtered = rows.filter((r) => {
    if (category !== "All" && r.category !== category) return false;
    if (username !== "All" && r.username !== username) return false;
    if (endpoint !== "All" && r.endpoint !== endpoint) return false;
    if (endpointId !== "All" && r.endpoint_id !== endpointId) return false;
    if (eventId !== "All" && String(r.event_id) !== String(eventId)) return false;
    if (search && !JSON.stringify(r).toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const pageRows = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  function resetPage(setter) {
    return (value) => {
      setter(value);
      setPage(1);
    };
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold text-slate-100">Events</h2>
        <p className="text-sm text-slate-500 mt-1">
          Real Windows Security events collected by <code className="text-slate-400">log-collector</code>.
        </p>
      </div>

      <DataModeBanner />

      <Card action={isDemo && <DemoTag />}>
        <div className="flex flex-wrap items-center gap-2 mb-4">
          <div className="relative flex-1 min-w-[200px]">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-500" />
            <input
              value={search}
              onChange={(e) => resetPage(setSearch)(e.target.value)}
              placeholder="Search events..."
              className="w-full bg-surface-raised border border-surface-border rounded-md pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none focus:ring-1 focus:ring-accent/50"
            />
          </div>
          <FilterSelect label="Category" value={category} options={categories} onChange={resetPage(setCategory)} />
          <FilterSelect label="User" value={username} options={usernames} onChange={resetPage(setUsername)} />
          <FilterSelect label="Computer" value={endpoint} options={endpoints} onChange={resetPage(setEndpoint)} />
          {!isDemo && (
            <FilterSelectObjects
              label="Enrolled Endpoint"
              value={endpointId}
              options={enrolledEndpointOptions}
              onChange={resetPage(setEndpointId)}
            />
          )}
          <FilterSelect label="Event ID" value={eventId} options={eventIds} onChange={resetPage(setEventId)} />
        </div>

        {isDemo ? (
          <>
            <DataTable
              columns={COLUMNS}
              rows={pageRows}
              onRowClick={setSelected}
              emptyIcon={ListTree}
              emptyTitle="No demo events match these filters"
            />
            <Pagination page={page} pageCount={pageCount} onPageChange={setPage} totalLabel={`${filtered.length} event(s)`} />
          </>
        ) : (
          <ResourceState
            resource={events}
            onReload={events.reload}
            notAvailableHint="An events listing endpoint has not been implemented on the backend yet."
          >
            {() => (
              <>
                <DataTable
                  columns={COLUMNS}
                  rows={pageRows}
                  onRowClick={setSelected}
                  emptyIcon={ListTree}
                  emptyTitle="No events to display yet"
                  emptyDescription="This table is wired to the real event schema and will populate once real events match these filters."
                />
                <Pagination page={page} pageCount={pageCount} onPageChange={setPage} totalLabel={`${filtered.length} event(s)`} />
              </>
            )}
          </ResourceState>
        )}
      </Card>

      <Drawer open={!!selected} onClose={() => setSelected(null)} title="Event Details">
        {selected && (
          <div className="space-y-3">
            {isDemo && <DemoTag />}
            <DetailRow label="Timestamp" value={selected.timestamp} />
            <DetailRow label="Event ID" value={selected.event_id} />
            <DetailRow label="Provider / Source" value={selected.source} />
            <DetailRow label="Username" value={selected.username} />
            <DetailRow label="Account Classification" value={selected.account_type} />
            <DetailRow label="Category" value={selected.category} />
            <DetailRow label="Computer" value={selected.endpoint} />
            <DetailRow label="Enrolled Endpoint" value={selected.endpoint_id} />
            {selected._eventLabel && <DetailRow label="Event Type" value={selected._eventLabel} />}
            {selected._status && <DetailRow label="Status" value={selected._status} />}
          </div>
        )}
      </Drawer>
    </div>
  );
}

function DetailRow({ label, value }) {
  return (
    <div className="flex items-center justify-between border-b border-surface-border/60 pb-2">
      <span className="text-xs text-slate-500">{label}</span>
      <span className="text-sm text-slate-200">{value ?? "—"}</span>
    </div>
  );
}

function FilterSelect({ label, value, options, onChange }) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      aria-label={label}
      className="bg-surface-raised border border-surface-border rounded-md px-2 py-1.5 text-xs text-slate-300 focus:outline-none focus:ring-1 focus:ring-accent/50"
    >
      {options.map((opt) => (
        <option key={opt} value={opt}>
          {label}: {opt}
        </option>
      ))}
    </select>
  );
}

/** Like FilterSelect, but options are `{ value, label }` pairs — used for
 * the real enrolled-endpoint filter, where the underlying value
 * (endpoint_id, a UUID) isn't what should be shown to the user. */
function FilterSelectObjects({ label, value, options, onChange }) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      aria-label={label}
      className="bg-surface-raised border border-surface-border rounded-md px-2 py-1.5 text-xs text-slate-300 focus:outline-none focus:ring-1 focus:ring-accent/50"
    >
      {options.map((opt) => (
        <option key={opt.value} value={opt.value}>
          {label}: {opt.label}
        </option>
      ))}
    </select>
  );
}
