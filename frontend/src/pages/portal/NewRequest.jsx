import { Loader2, ShieldAlert } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { createEndpointRequest, errorText, getMe } from "../../api/portal.js";
import Card from "../../components/ui/Card.jsx";
import { CONSENT_TEXT, NEVER_COLLECTED, SCOPES } from "./portalContent.js";

const INPUT =
  "mt-1 w-full bg-surface border border-surface-border rounded-md px-3 py-2 text-sm text-slate-200 focus:outline-none focus:ring-1 focus:ring-accent/50";

/** Transparent, UNVERIFIED browser hint. A website cannot reliably read the
 * Windows computer name; the agent reports the real identity at install time. */
function browserHint() {
  const platform = (navigator.userAgentData?.platform || navigator.platform || "").slice(0, 60);
  const ua = navigator.userAgent || "";
  return { platform, is_windows: /win/i.test(platform) || /windows/i.test(ua), user_agent: ua.slice(0, 300) };
}

export default function NewRequest() {
  const navigate = useNavigate();
  const hint = useMemo(browserHint, []);
  const [organization, setOrganization] = useState("");
  const [department, setDepartment] = useState("");
  const [justification, setJustification] = useState("");
  const [scope, setScope] = useState(["authentication"]);
  const [consent, setConsent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    getMe()
      .then((me) => setOrganization((cur) => cur || me.organization || ""))
      .catch(() => {});
  }, []);

  const canSubmit = consent && scope.length > 0 && organization.trim().length >= 2 && !busy;

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const created = await createEndpointRequest({
        organization: organization.trim(),
        department: department.trim() || undefined,
        justification: justification.trim() || undefined,
        requested_scope: scope,
        consent_acknowledged: consent,
        client_hint: hint,
      });
      navigate(`/portal/requests/${created.id}`, { state: { justSubmitted: true } });
    } catch (err) {
      setError(errorText(err, "The request could not be submitted."));
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-6" aria-label="Endpoint request form">
      <div>
        <h2 className="text-xl font-semibold text-slate-100">Request to use the UBADS Agent</h2>
        <p className="mt-1 text-sm text-slate-500">
          Tell the administrator what you want to monitor and why. Nothing is installed or collected until it is approved and you install the agent yourself.
        </p>
      </div>

      <Card title="About this request">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <label className="block text-xs text-slate-400">
            Organization <span className="text-status-danger">*</span>
            <input value={organization} onChange={(e) => setOrganization(e.target.value)} required minLength={2} maxLength={120} className={INPUT} />
          </label>
          <label className="block text-xs text-slate-400">
            Department (optional)
            <input value={department} onChange={(e) => setDepartment(e.target.value)} maxLength={120} className={INPUT} />
          </label>
        </div>
        <label className="mt-4 block text-xs text-slate-400">
          Justification (optional)
          <textarea
            value={justification}
            onChange={(e) => setJustification(e.target.value)}
            rows={3}
            maxLength={1000}
            placeholder="e.g. Research laptop used for the UBADS behaviour-analysis study"
            className={INPUT}
          />
        </label>
      </Card>

      <Card title="Monitoring scope">
        <fieldset>
          <legend className="mb-2 text-xs text-slate-500">Choose only what you need. The administrator may approve less, never more.</legend>
          <div className="space-y-2">
            {SCOPES.map((s) => (
              <label key={s.key} className="flex items-start gap-3 rounded-md border border-surface-border bg-surface-raised/40 p-3">
                <input
                  type="checkbox"
                  className="mt-0.5"
                  checked={scope.includes(s.key)}
                  onChange={(e) => setScope((cur) => (e.target.checked ? [...cur, s.key] : cur.filter((k) => k !== s.key)))}
                />
                <span>
                  <span className="block text-sm text-slate-200">{s.label}</span>
                  <span className="block text-xs text-slate-500">{s.description}</span>
                </span>
              </label>
            ))}
          </div>
        </fieldset>
        <div className="mt-4 rounded-md border border-surface-border p-3">
          <p className="text-xs font-medium text-slate-300">UBADS never collects:</p>
          <p className="mt-1 text-xs text-slate-500">{NEVER_COLLECTED.join(" · ")}</p>
        </div>
      </Card>

      <Card title="Browser compatibility check">
        <p className="text-xs text-slate-500">
          What this browser reports (sent with your request as an <em>unverified hint</em> only). The real computer name comes from the agent when it is installed.
        </p>
        <p className="mt-2 text-sm text-slate-300">
          Platform: <span className="text-slate-100">{hint.platform || "unknown"}</span> ·{" "}
          {hint.is_windows ? (
            <span className="text-status-ok">Windows detected - the agent can run here.</span>
          ) : (
            <span className="text-status-warn">This does not look like Windows. The agent is Windows-only; request access from the Windows computer you want to monitor.</span>
          )}
        </p>
      </Card>

      <Card title="Consent">
        <label className="flex items-start gap-3">
          <input type="checkbox" className="mt-1" checked={consent} onChange={(e) => setConsent(e.target.checked)} aria-describedby="consent-text" />
          <span id="consent-text" className="text-sm text-slate-300">{CONSENT_TEXT}</span>
        </label>
      </Card>

      {error && (
        <div role="alert" className="flex items-start gap-2 rounded-lg border border-status-danger/30 bg-status-danger/5 px-4 py-3 text-sm text-status-danger">
          <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
          {error}
        </div>
      )}

      <div className="flex items-center gap-3">
        <button
          type="submit"
          disabled={!canSubmit}
          className="inline-flex items-center gap-2 rounded-md border border-accent/30 bg-accent/10 px-4 py-2 text-sm font-medium text-accent hover:bg-accent/20 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {busy && <Loader2 className="h-4 w-4 animate-spin" />}
          Submit request
        </button>
        <Link to="/portal" className="text-sm text-slate-500 hover:text-slate-300">Cancel</Link>
      </div>
    </form>
  );
}
