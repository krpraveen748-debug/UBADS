import { CheckCircle2, Download, Info } from "lucide-react";
import { Link, useLocation, useParams } from "react-router-dom";
import { getMyRequest } from "../../api/portal.js";
import Card from "../../components/ui/Card.jsx";
import ResourceState from "../../components/ui/ResourceState.jsx";
import StatusBadge from "../../components/ui/StatusBadge.jsx";
import { useApiResource } from "../../hooks/useApiResource.js";
import { STATUS_TONE, formatDate, statusMessage } from "./portalContent.js";

const CONNECTION_TONE = { online: "ok", stale: "warn", offline: "danger" };

export default function RequestDetail() {
  const { id } = useParams();
  const { state } = useLocation();
  const resource = useApiResource(() => getMyRequest(id), [id]);

  return (
    <div className="space-y-6">
      <Link to="/portal" className="text-xs text-slate-500 hover:text-slate-300">← All requests</Link>

      {state?.justSubmitted && (
        <div role="status" className="flex items-center gap-2 rounded-lg border border-status-ok/30 bg-status-ok/5 px-4 py-2 text-sm text-slate-300">
          <CheckCircle2 className="h-4 w-4 text-status-ok" /> Request submitted. An administrator has been notified.
        </div>
      )}

      <ResourceState resource={resource} onReload={resource.reload} notAvailableHint="This request does not exist, or it does not belong to your account.">
        {(req) => <Detail req={req} />}
      </ResourceState>
    </div>
  );
}

function Detail({ req }) {
  const message = statusMessage(req);
  const narrowed = req.approved_scope && req.approved_scope.join() !== req.requested_scope.join();
  return (
    <>
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="text-xl font-semibold text-slate-100">Request details</h2>
        <StatusBadge status={STATUS_TONE[req.status] || "idle"} label={req.status} />
      </div>

      <section aria-label="Status" className="rounded-lg border border-surface-border bg-surface-card p-4">
        <p className="flex items-center gap-2 text-sm font-semibold text-slate-100">
          <Info className="h-4 w-4 text-accent" /> {message.title}
        </p>
        <p className="mt-1 text-sm text-slate-400">{message.body}</p>
        {(req.status === "APPROVED" || req.status === "ENROLLMENT_PENDING") && (
          <>
            <p className="mt-2 text-xs text-slate-500">Approval valid until {formatDate(req.approval_expires_at)}.</p>
            <Link
              to={`/portal/requests/${req.id}/download`}
              className="mt-3 inline-flex items-center gap-2 rounded-md border border-accent/30 bg-accent/10 px-4 py-2 text-sm font-medium text-accent hover:bg-accent/20"
            >
              <Download className="h-4 w-4" /> Go to installer download
            </Link>
          </>
        )}
        {req.status === "ENROLLED" && (
          <p className="mt-2 text-xs text-slate-400">
            Connection:{" "}
            {req.endpoint_connection_status ? (
              <StatusBadge status={CONNECTION_TONE[req.endpoint_connection_status] || "idle"} label={req.endpoint_connection_status} />
            ) : (
              "unknown"
            )}
          </p>
        )}
      </section>

      <Card title="Request">
        <dl className="grid grid-cols-1 gap-3 text-sm sm:grid-cols-2">
          <Row label="Organization" value={req.organization} />
          <Row label="Department" value={req.department} />
          <Row label="Submitted" value={formatDate(req.created_at)} />
          <Row label="Last decision" value={req.decided_at ? formatDate(req.decided_at) : "—"} />
          <Row label="Consent notice version" value={req.consent_version} />
          <Row label="Browser hint (unverified)" value={req.client_hint?.platform} />
        </dl>
        <div className="mt-4">
          <h4 className="mb-1.5 text-xs uppercase tracking-wide text-slate-500">Justification</h4>
          <p className="whitespace-pre-wrap text-sm text-slate-300">{req.justification || "—"}</p>
        </div>
      </Card>

      <Card title="Monitoring scope">
        <Chips label="Requested" items={req.requested_scope} />
        {req.approved_scope && (
          <div className="mt-3">
            <Chips label="Approved" items={req.approved_scope} />
            {narrowed && <p className="mt-1 text-xs text-status-warn">The administrator approved less than you asked for.</p>}
          </div>
        )}
      </Card>
    </>
  );
}

function Row({ label, value }) {
  return (
    <div className="border-b border-surface-border/60 pb-2">
      <dt className="text-xs text-slate-500">{label}</dt>
      <dd className="break-words text-slate-200">{value || "—"}</dd>
    </div>
  );
}

function Chips({ label, items }) {
  return (
    <div>
      <p className="mb-1 text-xs text-slate-500">{label}</p>
      <div className="flex flex-wrap gap-1.5">
        {items.map((s) => (
          <span key={s} className="rounded-full border border-surface-border bg-surface-raised px-2.5 py-0.5 text-xs text-slate-300">
            {s}
          </span>
        ))}
      </div>
    </div>
  );
}
