import { AlertTriangle } from "lucide-react";
import { useState } from "react";
import {
  getAnomalies,
  getAnomalyModelStatus,
  getSyntheticExperimentSamples,
  getSyntheticExperimentSummary,
  trainAnomalyModels,
} from "../api/endpoints.js";
import { DemoTag, RiskBadge } from "../components/ui/Badge.jsx";
import Card from "../components/ui/Card.jsx";
import DataModeBanner from "../components/ui/DataModeBanner.jsx";
import DataTable from "../components/ui/DataTable.jsx";
import EmptyState from "../components/ui/EmptyState.jsx";
import ResourceState from "../components/ui/ResourceState.jsx";
import StatCard from "../components/ui/StatCard.jsx";
import { useDataMode } from "../context/DataModeContext.jsx";
import { demoAnomalies, demoAnomalySummary } from "../demo/demoData.js";
import { useApiResource } from "../hooks/useApiResource.js";

const COLUMNS = [
  { key: "timestamp", label: "Detected" },
  { key: "user", label: "User / Profile" },
  { key: "endpoint", label: "Endpoint" },
  { key: "type", label: "Observation Window" },
  { key: "riskBadge", label: "Risk" },
  { key: "score", label: "Score" },
  { key: "reason", label: "Reason" },
  { key: "status", label: "Status" },
];

function withRiskBadge(rows) {
  return rows.map((r) => ({ ...r, riskBadge: <RiskBadge risk={r.risk} /> }));
}

function summaryCards(summary) {
  return [
    { label: "Total Anomalies", value: summary.total },
    { label: "High Risk", value: summary.high },
    { label: "Medium Risk", value: summary.medium },
    { label: "Low Risk", value: summary.low },
  ];
}

export default function Anomalies() {
  const { isLive, isDemo } = useDataMode();
  const anomalies = useApiResource(getAnomalies, [], { enabled: isLive });
  const modelStatus = useApiResource(getAnomalyModelStatus, [], { enabled: isLive });
  const syntheticSummary = useApiResource(getSyntheticExperimentSummary, [], { enabled: isLive });
  const syntheticSamples = useApiResource(getSyntheticExperimentSamples, [], { enabled: isLive });
  const [training, setTraining] = useState(false);
  const [trainingMessage, setTrainingMessage] = useState("");

  async function trainModels() {
    setTraining(true);
    setTrainingMessage("");
    try {
      const result = await trainAnomalyModels();
      const trained = result.trained_profiles?.length ?? 0;
      const insufficient = result.insufficient_profiles?.length ?? 0;
      setTrainingMessage(`Trained ${trained} profile(s); ${insufficient} need more completed windows.`);
      modelStatus.reload();
    } catch (error) {
      setTrainingMessage(error?.response?.data?.detail || "Model training failed. Check backend logs.");
    } finally {
      setTraining(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold text-slate-100">Anomalies</h2>
        <p className="text-sm text-slate-500 mt-1">Detected behavioral anomalies and investigation detail.</p>
      </div>

      <DataModeBanner />

      {isDemo ? (
        <>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            {summaryCards(demoAnomalySummary).map((c) => (
              <StatCard key={c.label} label={c.label} value={c.value} hint="DEMO" />
            ))}
          </div>
          <Card title="Anomaly Results" action={<DemoTag>SYNTHETIC DEMONSTRATION</DemoTag>}>
            <DataTable columns={COLUMNS} rows={withRiskBadge(demoAnomalies)} emptyIcon={AlertTriangle} />
            <p className="text-xs text-slate-600 mt-3">
              These are scripted, illustrative results — not output from a real trained anomaly-detection model. Run
              scenarios in <span className="text-accent">Demo Lab</span> to see how each one is explained.
            </p>
          </Card>
        </>
      ) : (
        <>
          <Card
            title="Isolation Forest Model Status"
            action={
              <button
                type="button"
                onClick={trainModels}
                disabled={training}
                className="rounded border border-surface-border px-3 py-1.5 text-xs text-slate-200 hover:bg-surface-raised disabled:opacity-50"
              >
                {training ? "Training…" : "Train / retrain"}
              </button>
            }
          >
            {modelStatus.loading ? (
              <p className="text-sm text-slate-400">Loading model status…</p>
            ) : modelStatus.unreachable ? (
              <p className="text-sm text-rose-300">Model status is unavailable.</p>
            ) : (
              <>
                <p className="text-sm text-slate-300">
                  {modelStatus.data?.trained_profiles ?? 0} trained profile(s);{" "}
                  {modelStatus.data?.insufficient_profiles ?? 0} profile(s) need more data.
                </p>
                <div className="mt-2 flex flex-wrap gap-2">
                  {(modelStatus.data?.profiles ?? []).map((profile) => (
                    <span
                      key={profile.profile_id}
                      className="rounded bg-surface-raised px-2 py-1 text-xs text-slate-400"
                    >
                      {profile.username || profile.profile_id} · {profile.status} · {profile.completed_windows}/
                      {profile.required_windows} completed windows
                      {profile.training_data_source ? ` · ${profile.training_data_source}` : ""}
                    </span>
                  ))}
                </div>
              </>
            )}
            {trainingMessage && <p role="status" className="mt-3 text-xs text-slate-400">{trainingMessage}</p>}
            <p className="mt-3 text-xs text-slate-500">
              Scores combine Isolation Forest output with profile deviation; they are not probabilities or incident determinations.
              Training requires at least 20 completed daily windows per endpoint/user profile.
            </p>
          </Card>
          <Card title="Experimental Synthetic Behaviour Risk" action={<DemoTag>SYNTHETIC EXPERIMENT</DemoTag>}>
            {syntheticSummary.loading ? (
              <p className="text-sm text-slate-400">Loading experimental results…</p>
            ) : syntheticSummary.notAvailable ? (
              <p className="text-sm text-slate-500">No synthetic experiment output is available.</p>
            ) : (
              <>
                <p className="text-sm text-slate-300">
                  {syntheticSummary.data?.scored_count ?? 0} scored sample(s);{" "}
                  {syntheticSummary.data?.synthetic_normal_count ?? 0} normal and{" "}
                  {syntheticSummary.data?.synthetic_abnormal_count ?? 0} abnormal.
                </p>
                <p className="mt-1 text-xs text-amber-300">
                  Experimental only · reference confidence:{" "}
                  {(syntheticSummary.data?.reference_confidence ?? []).join(", ") || "unknown"} · not production telemetry.
                </p>
                <div className="mt-3 space-y-2">
                  {(syntheticSamples.data?.items ?? []).map((sample) => (
                    <div key={sample.sample_id} className="rounded border border-surface-border px-3 py-2 text-xs">
                      <span className="text-slate-200">{sample.sample_id}</span>{" "}
                      <span className="text-slate-500">{sample.synthetic_behavior_type}</span>{" "}
                      <span className="text-accent">
                        behaviour risk: {sample.behavior_risk_score == null ? "unavailable" : Number(sample.behavior_risk_score).toFixed(2)}/100
                      </span>
                      <span className="ml-2 text-slate-500">
                        anomaly score: {Number(sample.anomaly_score).toFixed(3)}
                      </span>
                    </div>
                  ))}
                </div>
              </>
            )}
          </Card>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            {(() => {
              const list = Array.isArray(anomalies.data?.items) ? anomalies.data.items : [];
              const severityCounts = anomalies.data?.severity_counts ?? {};
              const summary = {
                total: anomalies.data?.total ?? 0,
                high: severityCounts.High ?? 0,
                medium: severityCounts.Medium ?? 0,
                low: severityCounts.Low ?? 0,
              };
              const cards = summaryCards(summary);
              if (anomalies.loading) return cards.map((c) => <StatCard key={c.label} label={c.label} value="…" hint="Loading" />);
              if (anomalies.notAvailable) return cards.map((c) => <StatCard key={c.label} label={c.label} value="--" hint="Not available yet" />);
              if (anomalies.unreachable) return cards.map((c) => <StatCard key={c.label} label={c.label} value="--" hint="Backend unavailable" />);
              return cards.map((c) => <StatCard key={c.label} label={c.label} value={c.value} hint="Live" />);
            })()}
          </div>

          <Card title="Anomaly Results">
            <ResourceState
              resource={anomalies}
              onReload={anomalies.reload}
              notAvailableHint="Anomaly detections are not available from the backend."
            >
              {(data) => {
                const list = Array.isArray(data?.items) ? data.items.map((anomaly) => ({
                  id: anomaly.id,
                  timestamp: new Date(anomaly.detected_at).toLocaleString(),
                  user: anomaly.username || anomaly.profile_id,
                  endpoint: anomaly.endpoint_id,
                  type: `${anomaly.window_size}: ${new Date(anomaly.window_start).toLocaleString()}`,
                  risk: anomaly.severity,
                  score: anomaly.anomaly_score.toFixed(3),
                  reason: (anomaly.explanation?.features ?? [])
                    .map((item) => `${item.feature} ${item.direction} baseline (${item.observed} vs ${item.baseline_median})`)
                    .join("; ") || "No large individual feature deviation",
                  status: `${anomaly.training_data_source} · ${anomaly.model_version}`,
                })) : [];
                if (list.length === 0) {
                  return (
                    <EmptyState
                      icon={AlertTriangle}
                      title="No anomaly results available yet"
                      description="No real model detections are recorded. The dashboard does not fabricate anomaly counts or scores."
                      action={{ label: "Try Demo Lab", to: "/demo-lab" }}
                    />
                  );
                }
                return <DataTable columns={COLUMNS} rows={withRiskBadge(list)} />;
              }}
            </ResourceState>
          </Card>
        </>
      )}
    </div>
  );
}
