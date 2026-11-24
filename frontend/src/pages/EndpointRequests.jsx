import { CheckCircle2, ClipboardList, Clock, Search, ShieldOff, XCircle } from "lucide-react";
import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  approveEndpointRequest,
  getAdminEndpointRequest,
  getAdminEndpointRequests,
  rejectEndpointRequest,
  revokeEndpointRequest,
} from "../api/endpoints.js";
import Card from "../components/ui/Card.jsx";
import ConfirmDialog from "../components/ui/ConfirmDialog.jsx";
import DataTable from "../components/ui/DataTable.jsx";
import Drawer from "../components/ui/Drawer.jsx";
import ResourceState from "../components/ui/ResourceState.jsx";
import StatCard from "../components/ui/StatCard.jsx";
import StatusBadge from "../components/ui/StatusBadge.jsx";
import { useApiResource } from "../hooks/useApiResource.js";

const STATUSES = ["PENDING", "APPROVED", "ENROLLMENT_PENDING", "ENROLLED", "REJECTED", "REVOKED", "EXPIRED"];
const STATUS_TONE = {
  PENDING: "warn",
  APPROVED: "info",
  ENROLLMENT_PENDING: "info",
  ENROLLED: "ok",
  REJECTED: "danger",
  REVOKED: "danger",
  EXPIRED: "idle",
};

function fmt(value) {
  if (!value) return "—";
  const d = new Date(value.endsWith("Z") || value.includes("+") ? value : `${value}Z`);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString();
}

const COLUMNS = [
  { key: "requester", label: "Requester" },
  { key: "organization", label: "Organization / Dept." },
  { key: "scope", label: "Requested scope" },
  { key: "submitted", label: "Submitted" },
  { key: "statusBadge", label: "Status" },
];

function toRow(r) {
  return {
    ...r,
    requester: (
      <div className="leading-tight">
        <p className="text-slate-200">{r.requester_full_name || r.username}</p>
        <p className="text-xs text-slate-500">{r.requester_email || r.username}</p>
      </div>
    ),
    organization: (
      <div className="leading-tight">
        <p>{r.organization}</p>
        <p className="text-xs text-slate-500">{r.department || "—"}</p>
      </div>
    ),
    scope: r.requested_scope.map((s) => s.replace("_activity", "")).join(", "),
    submitted: fmt(r.created_at),
    statusBadge: <StatusBadge status={STATUS_TONE[r.status] || "idle"} label={r.status} />,
  };
}

export default function EndpointRequests() {
  const [status, setStatus] = useState("");
  const [search, setSearch] = useState("");
  const [query, setQuery] = useState("");
  const [reloadKey, setReloadKey] = useState(0);
  const [searchParams, setSearchParams] = useSearchParams();
  const [selectedId, setSelectedIdState] = useState(searchParams.get("request"));
  const setSelectedId = (id) => {
    setSelectedIdState(id);
    setSearchParams(id ? { request: id } : {}, { replace: true });
  };
  useEffect(() => {
    // a notification link (or the browser back button) can change ?request=
    const fromUrl = searchParams.get("request");
    if (fromUrl !== selectedId) setSelectedIdState(fromUrl);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams]);
  const [detail, setDetail] = useState({ loading: false, data: null, error: null });
  const [dialog, setDialog] = useState(null); // "approve" | "reject" | "revoke"
  const [approveScope, setApproveScope] = useState([]);
  const [notice, setNotice] = useState(null);

  useEffect(() => {
    const t = setTimeout(() => setQuery(search.trim()), 300);
    return () => clearTimeout(t);
  }, [search]);

  const list = useApiResource(
    () => getAdminEndpointRequests({ limit: 200, ...(status ? { status } : {}), ...(query ? { q: query } : {}) }),
    [status, query, reloadKey]
  );

  useEffect(() => {
    if (!selectedId) return;
    let cancelled = false;
    setDetail({ loading: true, data: null, error: null });
    getAdminEndpointRequest(selectedId)
      .then((data) => !cancelled && setDetail({ loading: false, data, error: null }))
      .catch((err) =>
        !cancelled &&
        setDetail({ loading: false, data: null, error: err?.response?.data?.detail || err?.message || "Could not load request." })
      );
    return () => {
      cancelled = true;
    };
  }, [selectedId, reloadKey]);

  const refresh = () => setReloadKey((k) => k + 1);
  const req = detail.data;

  function openApprove() {
    setApproveScope(req.requested_scope);
    setDialog("approve");
  }

  async function finish(message) {
    setDialog(null);
    setNotice(message);
    refresh();
  }

  const counts = list.data?.counts || {};

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold text-slate-100">Endpoint Requests</h2>
        <p className="text-sm text-slate-500 mt-1">
          Review users' requests to install the UBADS agent. Approving does not install anything by itself.
        </p>
      </div>

      {notice && (
        <div role="status" className="flex items-center justify-between rounded-lg border border-status-ok/30 bg-status-ok/5 px-4 py-2 text-xs text-slate-300">
          {notice}
          <button onClick={() => setNotice(null)} className="text-slate-500 hover:text-slate-200" aria-label="Dismiss">
            ×
          </button>
        </div>
      )}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard icon={Clock} label="Pending" value={counts.PENDING ?? "—"} />
        <StatCard icon={CheckCircle2} label="Approved" value={counts.APPROVED ?? "—"} hint="Awaiting installation" />
        <StatCard icon={ClipboardList} label="Enrolled" value={counts.ENROLLED ?? "—"} hint={counts.ENROLLMENT_PENDING ? `${counts.ENROLLMENT_PENDING} awaiting enrollment` : undefined} />
        <StatCard icon={XCircle} label="Rejected / Revoked" value={list.data ? (counts.REJECTED ?? 0) + (counts.REVOKED ?? 0) : "—"} />
      </div>

      <Card>
        <div className="flex flex-wrap items-center gap-2 mb-4">
          <div className="relative flex-1 min-w-[200px]">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-500" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search requester, email or organization..."
              aria-label="Search requests"
              className="w-full bg-surface-raised border border-surface-border rounded-md pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none focus:ring-1 focus:ring-accent/50"
            />
          </div>
          <label className="flex items-center gap-2 text-xs text-slate-500">
            Status
            <select
              value={status}
              onChange={(e) => setStatus(e.target.value)}
              className="bg-surface-raised border border-surface-border rounded-md px-2 py-1.5 text-xs text-slate-200"
            >
              <option value="">All (history)</option>
              {STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </label>
        </div>

        <ResourceState resource={list} onReload={list.reload}>
          {(data) => (
            <DataTable
              columns={COLUMNS}
              rows={(data?.items || []).map(toRow)}
              onRowClick={(row) => setSelectedId(row.id)}
              emptyIcon={ClipboardList}
              emptyTitle={status || query ? "No requests match these filters" : "No endpoint requests yet"}
              emptyDescription="Requests appear here when users ask to install the UBADS agent."
            />
          )}
        </ResourceState>
      </Card>

      <Drawer open={!!selectedId} onClose={() => setSelectedId(null)} title="Request details">
        {detail.loading && <p className="text-sm text-slate-500">Loading...</p>}
        {detail.error && (
          <p role="alert" className="text-sm text-status-danger">
            {detail.error}
          </p>
        )}
        {req && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <StatusBadge status={STATUS_TONE[req.status] || "idle"} label={req.status} />
              {req.endpoint_connection_status && (
                <StatusBadge
                  status={{ online: "ok", stale: "warn", offline: "danger" }[req.endpoint_connection_status] || "idle"}
                  label={`Endpoint ${req.endpoint_connection_status}`}
                />
              )}
            </div>

            <dl className="space-y-2 text-sm">
              <Row label="Requester" value={`${req.requester_full_name || "—"} (${req.username})`} />
              <Row label="Email" value={req.requester_email} />
              <Row label="Organization" value={req.organization} />
              <Row label="Department" value={req.department} />
              <Row label="Submitted" value={fmt(req.created_at)} />
              <Row label="Consent version" value={req.consent_version} />
              <Row label="Browser hint (unverified)" value={req.client_hint ? `${req.client_hint.platform ?? "?"}` : null} />
            </dl>

            <Section title="Requested monitoring scope">
              <ScopeChips scopes={req.requested_scope} />
            </Section>
            {req.approved_scope && (
              <Section title="Approved scope">
                <ScopeChips scopes={req.approved_scope} />
              </Section>
            )}
            <Section title="Justification">
              <p className="text-sm text-slate-300 whitespace-pre-wrap">{req.justification || "—"}</p>
            </Section>
            {(req.decided_by || req.status_reason) && (
              <Section title="Decision">
                <p className="text-xs text-slate-500">
                  {req.decided_by ? `By ${req.decided_by} · ${fmt(req.decided_at)}` : ""}
                </p>
                {req.status_reason && <p className="text-sm text-slate-300 mt-1">{req.status_reason}</p>}
                {req.status === "APPROVED" && (
                  <p className="text-xs text-slate-500 mt-1">Approval valid until {fmt(req.approval_expires_at)}</p>
                )}
              </Section>
            )}
            {req.endpoint_id && (
              <Section title="Enrolled endpoint">
                <p className="text-xs text-slate-400 break-all">{req.endpoint_id}</p>
              </Section>
            )}

            <div className="flex flex-wrap gap-2 pt-1">
              {req.status === "PENDING" && (
                <>
                  <button onClick={openApprove} className="rounded-md border border-accent/30 bg-accent/10 px-3 py-1.5 text-xs font-medium text-accent hover:bg-accent/20">
                    Approve
                  </button>
                  <button onClick={() => setDialog("reject")} className="rounded-md border border-status-danger/40 bg-status-danger/10 px-3 py-1.5 text-xs font-medium text-status-danger hover:bg-status-danger/20">
                    Reject
                  </button>
                </>
              )}
              {["APPROVED", "ENROLLMENT_PENDING", "ENROLLED"].includes(req.status) && (
                <button onClick={() => setDialog("revoke")} className="inline-flex items-center gap-1.5 rounded-md border border-status-danger/40 bg-status-danger/10 px-3 py-1.5 text-xs font-medium text-status-danger hover:bg-status-danger/20">
                  <ShieldOff className="h-3 w-3" />
                  Revoke
                </button>
              )}
            </div>

            <Section title="Audit history">
              {req.audit_history?.length ? (
                <ol className="space-y-2">
                  {req.audit_history.map((a) => (
                    <li key={a.id} className="border-l-2 border-surface-border pl-3">
                      <p className="text-xs text-slate-200">
                        {a.action} <span className="text-slate-500">· {a.actor || "system"}</span>
                      </p>
                      <p className="text-[11px] text-slate-500">{fmt(a.at)}</p>
                      {a.detail && <p className="text-[11px] text-slate-500 break-words">{a.detail}</p>}
                    </li>
                  ))}
                </ol>
              ) : (
                <p className="text-xs text-slate-500">No audit entries.</p>
              )}
            </Section>
          </div>
        )}
      </Drawer>

      <ConfirmDialog
        open={dialog === "approve"}
        title="Approve this request?"
        message="The requester will be notified. You can narrow the monitoring scope; it can never be wider than requested."
        confirmLabel="Approve"
        confirmDisabled={approveScope.length === 0}
        reasonLabel="Note to requester (optional)"
        onCancel={() => setDialog(null)}
        onConfirm={async (note) => {
          await approveEndpointRequest(req.id, { approved_scope: approveScope, note: note || undefined });
          await finish("Request approved. The requester has been notified.");
        }}
      >
        {req && (
          <fieldset className="space-y-1">
            <legend className="text-xs text-slate-400 mb-1">Approved monitoring scope</legend>
            {req.requested_scope.map((s) => (
              <label key={s} className="flex items-center gap-2 text-sm text-slate-300">
                <input
                  type="checkbox"
                  checked={approveScope.includes(s)}
                  onChange={(e) => setApproveScope((cur) => (e.target.checked ? [...cur, s] : cur.filter((x) => x !== s)))}
                />
                {s}
              </label>
            ))}
          </fieldset>
        )}
      </ConfirmDialog>

      <ConfirmDialog
        open={dialog === "reject"}
        title="Reject this request?"
        message="The requester will see your reason."
        confirmLabel="Reject"
        tone="danger"
        reasonLabel="Reason for rejection"
        reasonRequired
        onCancel={() => setDialog(null)}
        onConfirm={async (reason) => {
          await rejectEndpointRequest(req.id, reason);
          await finish("Request rejected. The requester has been notified.");
        }}
      />

      <ConfirmDialog
        open={dialog === "revoke"}
        title="Revoke this authorization?"
        message={
          req?.status === "ENROLLED"
            ? "The installed agent's credential will be invalidated immediately and it will no longer be able to upload events."
            : "The approval will be withdrawn and can no longer be used to install the agent."
        }
        confirmLabel="Revoke"
        tone="danger"
        reasonLabel="Reason (optional)"
        onCancel={() => setDialog(null)}
        onConfirm={async (reason) => {
          await revokeEndpointRequest(req.id, reason || undefined);
          await finish("Authorization revoked.");
        }}
      />
    </div>
  );
}

function Row({ label, value }) {
  return (
    <div className="flex justify-between gap-4 border-b border-surface-border/60 pb-2">
      <dt className="text-xs text-slate-500 shrink-0">{label}</dt>
      <dd className="text-slate-200 text-right break-words min-w-0">{value || "—"}</dd>
    </div>
  );
}

function Section({ title, children }) {
  return (
    <div>
      <h4 className="text-xs uppercase tracking-wide text-slate-500 mb-1.5">{title}</h4>
      {children}
    </div>
  );
}

function ScopeChips({ scopes }) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {scopes.map((s) => (
        <span key={s} className="rounded-full border border-surface-border bg-surface-raised px-2.5 py-0.5 text-xs text-slate-300">
          {s}
        </span>
      ))}
    </div>
  );
}
