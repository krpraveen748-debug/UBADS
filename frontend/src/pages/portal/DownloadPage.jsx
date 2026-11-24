import { Download, Loader2, LockKeyhole, ShieldCheck } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { downloadInstaller, errorText, getDownloadInfo } from "../../api/portal.js";
import Card from "../../components/ui/Card.jsx";
import { NEVER_COLLECTED, SCOPES, formatDate } from "./portalContent.js";

function formatSize(bytes) {
  return bytes ? `${(bytes / 1024 / 1024).toFixed(1)} MB` : "unknown size";
}

function packageErrorText(err) {
  switch (err?.response?.status) {
    case 401:
      return "Your session has expired. Sign in again to continue.";
    case 403:
      return "This request is no longer eligible for an installer. Check its status or contact an administrator.";
    case 404:
      return "This request does not exist, or it does not belong to your account.";
    case 410:
      return "This enrollment authorization has expired or has already been used. Return to your request for the current status.";
    case 429:
      return "An installer package was requested too recently. Please wait before trying again.";
    case 503:
      return "The installer is temporarily unavailable. Please contact an administrator.";
    default:
      return "The installer download failed. Please try again.";
  }
}

export default function DownloadPage() {
  const { id } = useParams();
  const [state, setState] = useState({ loading: true, info: null, error: null, status: null });
  const [dl, setDl] = useState({ busy: false, started: false, error: null });
  const downloadLocked = useRef(false);

  useEffect(() => {
    let cancelled = false;
    downloadLocked.current = false;
    setDl({ busy: false, started: false, error: null });
    setState({ loading: true, info: null, error: null, status: null });
    getDownloadInfo(id)
      .then((info) => !cancelled && setState({ loading: false, info, error: null, status: 200 }))
      .catch((err) =>
        !cancelled &&
        setState({
          loading: false,
          info: null,
          status: err?.response?.status ?? 0,
          error: err?.response?.status === 404 ? "This request does not exist, or it does not belong to your account." : errorText(err),
        })
      );
    return () => {
      cancelled = true;
    };
  }, [id]);

  async function start() {
    if (downloadLocked.current) return;
    downloadLocked.current = true;
    setDl({ busy: true, started: false, error: null });
    try {
      await downloadInstaller(id);
      setDl({ busy: false, started: true, error: null });
    } catch (err) {
      setDl({ busy: false, started: false, error: packageErrorText(err) });
      downloadLocked.current = false;
    }
  }

  if (state.loading) {
    return (
      <p className="flex items-center gap-2 py-14 text-sm text-slate-500">
        <Loader2 className="h-4 w-4 animate-spin" /> Checking your authorization...
      </p>
    );
  }

  if (state.error) {
    return (
      <div className="space-y-4">
        <Link to={`/portal/requests/${id}`} className="text-xs text-slate-500 hover:text-slate-300">← Back to request</Link>
        <div role="alert" className="flex items-start gap-3 rounded-lg border border-status-danger/30 bg-status-danger/5 p-4">
          <LockKeyhole className="mt-0.5 h-5 w-5 shrink-0 text-status-danger" />
          <div>
            <h2 className="text-base font-semibold text-slate-100">Installer not available</h2>
            <p className="mt-1 text-sm text-slate-400">{state.error}</p>
          </div>
        </div>
      </div>
    );
  }

  const { info } = state;
  const installer = info.installer;
  const scopes = SCOPES.filter((s) => info.approved_scope.includes(s.key));

  return (
    <div className="space-y-6">
      <Link to={`/portal/requests/${id}`} className="text-xs text-slate-500 hover:text-slate-300">← Back to request</Link>
      <div>
        <h2 className="text-xl font-semibold text-slate-100">Download the Windows agent</h2>
        <p className="mt-1 text-sm text-slate-500">
          Your request is approved until {formatDate(info.approval_expires_at)}. Approval does <strong>not</strong> install anything by itself - you install the agent on your own computer.
        </p>
      </div>

      <Card title="UBADS Windows Agent installer">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="text-sm">
            <p className="text-slate-200">Endpoint-specific enrollment package</p>
            <p className="text-xs text-slate-500">
              Windows 10/11 (64-bit) · {formatSize(installer.size_bytes)} · unsigned development build
            </p>
            {installer.sha256 && <p className="mt-1 break-all font-mono text-[11px] text-slate-600">SHA-256: {installer.sha256}</p>}
          </div>
          <button
            onClick={start}
            disabled={!installer.available || dl.busy || dl.started}
            className="inline-flex items-center gap-2 rounded-md border border-accent/30 bg-accent/10 px-4 py-2 text-sm font-medium text-accent hover:bg-accent/20 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {dl.busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}
            {dl.started ? "Package downloaded" : "Download installer"}
          </button>
        </div>
        {!installer.available && (
          <p role="alert" className="mt-3 text-sm text-status-danger">The installer is not available on this server right now. Please contact an administrator.</p>
        )}
        {dl.started && (
          <p role="status" className="mt-3 text-sm text-status-ok">Download started. Open the file from your Downloads folder to begin installing.</p>
        )}
        {dl.error && <p role="alert" className="mt-3 text-sm text-status-danger">{dl.error}</p>}
      </Card>

      <Card title="Installing on Windows">
        <ol className="list-decimal space-y-2 pl-5 text-sm text-slate-300">
          <li>
            The downloaded package contains a short-lived, single-use authorization in its filename. Do not rename or share it;
            install it only on the computer covered by this request.
          </li>
          <li>Open the downloaded installer on that Windows computer to enroll it automatically.</li>
          <li>
            Windows will ask for permission (User Account Control). Installing needs administrator rights, so approve it only if you
            trust this file. Because this is an unsigned build, Windows SmartScreen or your antivirus may also warn you - UBADS does not bypass these prompts.
          </li>
          <li>Follow the setup steps. The installer does not enable any Windows audit policy on its own.</li>
        </ol>
      </Card>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <Card title="Approved monitoring scope">
          <ul className="space-y-2">
            {scopes.map((s) => (
              <li key={s.key} className="flex items-start gap-2 text-sm">
                <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-status-ok" />
                <span><span className="text-slate-200">{s.label}</span><span className="block text-xs text-slate-500">{s.description}</span></span>
              </li>
            ))}
          </ul>
          <p className="mt-3 text-xs text-slate-500">Nothing outside this scope is approved for collection.</p>
        </Card>
        <Card title="Never collected">
          <ul className="list-disc space-y-1 pl-5 text-sm text-slate-300">
            {NEVER_COLLECTED.map((n) => (
              <li key={n}>{n}</li>
            ))}
          </ul>
        </Card>
      </div>

      <Card title="Uninstalling or withdrawing access">
        <p className="text-sm text-slate-300">
          You can uninstall the agent at any time from Windows <em>Settings → Apps → Installed apps → UBADS Windows Endpoint Agent</em>.
          To withdraw this authorization, ask an administrator to revoke it: the installer stops being available and the server stops accepting data from an agent installed under it.
        </p>
      </Card>
    </div>
  );
}
