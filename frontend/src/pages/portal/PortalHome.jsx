import { Inbox, Plus } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import { getMe, getMyRequests } from "../../api/portal.js";
import Card from "../../components/ui/Card.jsx";
import DataTable from "../../components/ui/DataTable.jsx";
import ResourceState from "../../components/ui/ResourceState.jsx";
import StatusBadge from "../../components/ui/StatusBadge.jsx";
import { useApiResource } from "../../hooks/useApiResource.js";
import { STATUS_TONE, formatDate } from "./portalContent.js";

const COLUMNS = [
  { key: "submitted", label: "Submitted" },
  { key: "organization", label: "Organization / Department" },
  { key: "scope", label: "Monitoring scope" },
  { key: "statusBadge", label: "Status" },
];

export default function PortalHome() {
  const navigate = useNavigate();
  const profile = useApiResource(getMe, []);
  const requests = useApiResource(getMyRequests, []);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-xl font-semibold text-slate-100">My endpoint requests</h2>
          <p className="mt-1 text-sm text-slate-500">
            Ask to install the UBADS agent on a computer you are authorised to monitor. An administrator reviews every request.
          </p>
        </div>
        <Link
          to="/portal/new"
          className="inline-flex items-center gap-2 rounded-md border border-accent/30 bg-accent/10 px-4 py-2 text-sm font-medium text-accent hover:bg-accent/20"
        >
          <Plus className="h-4 w-4" /> Request to use UBADS Agent
        </Link>
      </div>

      <Card title="Your account">
        <ResourceState resource={profile} onReload={profile.reload}>
          {(me) => (
            <dl className="grid grid-cols-1 gap-3 text-sm sm:grid-cols-2">
              <Field label="Name" value={me.full_name} />
              <Field label="Username" value={me.username} />
              <Field label="Email" value={me.email} />
              <Field label="Organization" value={me.organization} />
              <Field label="Account type" value="Standard user" />
            </dl>
          )}
        </ResourceState>
      </Card>

      <Card title="Request history">
        <ResourceState resource={requests} onReload={requests.reload}>
          {(list) => (
            <DataTable
              columns={COLUMNS}
              rows={(list || []).map((r) => ({
                ...r,
                submitted: formatDate(r.created_at),
                organization: (
                  <div className="leading-tight">
                    <p>{r.organization}</p>
                    <p className="text-xs text-slate-500">{r.department || "—"}</p>
                  </div>
                ),
                scope: r.requested_scope.map((s) => s.replace("_activity", "")).join(", "),
                statusBadge: <StatusBadge status={STATUS_TONE[r.status] || "idle"} label={r.status} />,
              }))}
              onRowClick={(row) => navigate(`/portal/requests/${row.id}`)}
              emptyIcon={Inbox}
              emptyTitle="You have not made any requests yet"
              emptyDescription="Use the button above to request access to the UBADS agent."
            />
          )}
        </ResourceState>
      </Card>
    </div>
  );
}

function Field({ label, value }) {
  return (
    <div className="border-b border-surface-border/60 pb-2">
      <dt className="text-xs text-slate-500">{label}</dt>
      <dd className="text-slate-200 break-words">{value || "—"}</dd>
    </div>
  );
}
