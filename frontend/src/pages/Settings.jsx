import { useState } from "react";
import { Link } from "react-router-dom";
import { API_BASE_URL } from "../api/client.js";
import { getHealth } from "../api/endpoints.js";
import Card from "../components/ui/Card.jsx";
import PrivacyNote from "../components/ui/PrivacyNote.jsx";
import StatusBadge from "../components/ui/StatusBadge.jsx";
import { useDataMode } from "../context/DataModeContext.jsx";

const APP_VERSION = "0.1.0";

export default function Settings() {
  const { mode, setMode } = useDataMode();
  const [checking, setChecking] = useState(false);
  const [result, setResult] = useState(null); // { ok: boolean, detail: string }

  async function handleTestConnection() {
    setChecking(true);
    setResult(null);
    try {
      const data = await getHealth();
      setResult({ ok: true, detail: `Reached backend: ${data.app_name} (${data.environment})` });
    } catch (err) {
      setResult({ ok: false, detail: `Could not reach backend at ${API_BASE_URL}: ${err.message}` });
    } finally {
      setChecking(false);
    }
  }

  const connectionStatus = result === null ? "idle" : result.ok ? "ok" : "danger";
  const connectionLabel = result === null ? "Unknown" : result.ok ? "Connected" : "Disconnected";

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold text-slate-100">Settings</h2>
        <p className="text-sm text-slate-500 mt-1">Backend connection and local pipeline configuration.</p>
      </div>

      <Card title="Backend API">
        <div className="space-y-3">
          <div className="flex items-center justify-between text-sm">
            <span className="text-slate-400">API Base URL</span>
            <code className="text-slate-200 bg-surface-raised border border-surface-border rounded px-2 py-1 text-xs">
              {API_BASE_URL}
            </code>
          </div>
          <p className="text-xs text-slate-600">
            Configured via <code className="text-slate-400">VITE_API_BASE_URL</code> in{" "}
            <code className="text-slate-400">frontend/.env</code> (see{" "}
            <code className="text-slate-400">frontend/.env.example</code>) — never hard-coded in components.
          </p>

          <div className="flex items-center gap-3 pt-2">
            <button
              onClick={handleTestConnection}
              disabled={checking}
              className="rounded-md bg-accent/10 border border-accent/30 text-accent text-sm px-3 py-1.5 hover:bg-accent/20 disabled:opacity-50 transition-colors"
            >
              {checking ? "Checking..." : "Test Connection"}
            </button>
            <StatusBadge status={connectionStatus} label={connectionLabel} />
          </div>
          {result && <p className="text-xs text-slate-500">{result.detail}</p>}
          {result === null && (
            <p className="text-xs text-slate-600">
              Status is only ever "Connected" once a real connection test succeeds — it is never assumed.
            </p>
          )}
        </div>
      </Card>

      <Card title="Endpoint Configuration">
        <p className="text-xs text-slate-500 mb-3">
          Endpoint enrollment and agent installation are managed from a dedicated page.
        </p>
        <Link to="/endpoint-enrollment" className="text-xs font-medium text-accent hover:underline">
          Go to Endpoint Enrollment →
        </Link>
      </Card>

      <Card title="Data Collection Configuration">
        <p className="text-xs text-slate-500 mb-2">
          Real ML-readiness status is produced by running, on the collection machine:
        </p>
        <pre className="text-xs bg-surface-raised border border-surface-border rounded p-3 text-slate-400 overflow-x-auto">
          cd ml-service{"\n"}python feature_engineering.py --collection-status
        </pre>
        <p className="mt-2 text-xs text-slate-600">
          This dashboard does not yet display that output directly — see the{" "}
          <Link to="/reports" className="text-accent hover:underline">
            Reports
          </Link>{" "}
          page for the prepared (not-yet-connected) view.
        </p>
      </Card>

      <Card title="Demo Mode">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm text-slate-300">Current data mode</p>
            <p className="text-xs text-slate-500 mt-0.5">
              Controls whether pages show real backend data or isolated synthetic demonstration data.
            </p>
          </div>
          <div className="flex items-center gap-1 rounded-md border border-surface-border p-0.5">
            <button
              onClick={() => setMode("live")}
              className={`px-3 py-1.5 text-xs rounded transition-colors ${
                mode === "live" ? "bg-accent/10 text-accent" : "text-slate-500 hover:text-slate-300"
              }`}
            >
              Live
            </button>
            <button
              onClick={() => setMode("demo")}
              className={`px-3 py-1.5 text-xs rounded transition-colors ${
                mode === "demo" ? "bg-status-warn/10 text-status-warn" : "text-slate-500 hover:text-slate-300"
              }`}
            >
              Demo
            </button>
          </div>
        </div>
      </Card>

      <Card title="Privacy / Data Collection">
        <PrivacyNote />
      </Card>

      <Card title="Application Information">
        <div className="space-y-1.5 text-xs">
          <div className="flex items-center justify-between">
            <span className="text-slate-500">Product</span>
            <span className="text-slate-300">UBADS — User Behavior Anomaly Detection System</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-slate-500">Frontend Version</span>
            <span className="text-slate-300">v{APP_VERSION}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-slate-500">Stack</span>
            <span className="text-slate-300">React + Vite + Tailwind CSS</span>
          </div>
        </div>
      </Card>
    </div>
  );
}
