import { FlaskConical, PlayCircle } from "lucide-react";
import { useState } from "react";
import Badge, { RiskBadge } from "../components/ui/Badge.jsx";
import Card from "../components/ui/Card.jsx";
import { useDataMode } from "../context/DataModeContext.jsx";
import { runScenario, SCENARIOS } from "../demo/scenarios/scenarios.js";

function ScenarioCard({ scenario, onRun, isRunning, result }) {
  return (
    <Card>
      <div className="flex items-start justify-between mb-2">
        <div>
          <p className="text-sm font-semibold text-slate-100">{scenario.title}</p>
          <Badge variant="slate" className="mt-1">
            {scenario.category}
          </Badge>
        </div>
      </div>

      <div className="mt-3 space-y-2 text-xs">
        <div className="rounded-md border border-surface-border bg-surface-raised/50 p-2.5">
          <p className="text-slate-500">{scenario.normalLabel}</p>
          <p className="text-slate-300 mt-0.5">{scenario.normalDescription}</p>
        </div>
        <div className="rounded-md border border-status-warn/30 bg-status-warn/5 p-2.5">
          <p className="text-status-warn">{scenario.simulatedLabel}</p>
          <p className="text-slate-300 mt-0.5">{scenario.simulatedDescription}</p>
        </div>
      </div>

      <button
        onClick={() => onRun(scenario)}
        disabled={isRunning}
        className="mt-4 w-full inline-flex items-center justify-center gap-2 rounded-md bg-accent/10 border border-accent/30 text-accent text-xs font-medium px-3 py-2 hover:bg-accent/20 disabled:opacity-50 transition-colors"
      >
        <PlayCircle className="h-3.5 w-3.5" />
        {isRunning ? "Running..." : "Run Scenario"}
      </button>

      {result && (
        <div className="mt-4 rounded-md border border-surface-border p-3 space-y-2">
          <div className="flex items-center justify-between">
            <Badge variant="warn">SIMULATED RESULT</Badge>
            <RiskBadge risk={result.riskLevel} />
          </div>
          <p className="text-xs text-slate-300">
            <span className="text-slate-500">Expected behavioral deviation: </span>
            {scenario.simulatedDescription}
          </p>
          <p className="text-xs text-slate-300">
            <span className="text-slate-500">Detected result: </span>
            {result.anomalyType}
          </p>
          <p className="text-xs text-slate-400">
            <span className="text-slate-500">Reason: </span>
            {result.reason}
          </p>
        </div>
      )}
    </Card>
  );
}

export default function DemoLab() {
  const { isDemo, setMode } = useDataMode();
  const [results, setResults] = useState({});
  const [running, setRunning] = useState(null);

  function handleRun(scenario) {
    setRunning(scenario.id);
    // Deliberately deterministic and synchronous — this is a scripted
    // walkthrough, not a real model call, so there's nothing to await.
    // A short delay only makes the "Running..." state visible/legible.
    setTimeout(() => {
      setResults((prev) => ({ ...prev, [scenario.id]: runScenario(scenario) }));
      setRunning(null);
    }, 500);
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold text-slate-100">Demo Lab</h2>
        <p className="text-sm text-slate-500 mt-1">
          Demonstrate what anomaly detection explanations will look like, without waiting for a real anomaly.
        </p>
      </div>

      <div className="flex items-start gap-3 rounded-lg border border-status-warn/30 bg-status-warn/5 px-4 py-3">
        <FlaskConical className="h-4 w-4 text-status-warn shrink-0 mt-0.5" strokeWidth={1.75} />
        <div>
          <p className="text-sm font-semibold text-status-warn tracking-wide">DEMO MODE</p>
          <p className="text-xs text-slate-500 mt-1">
            Synthetic data is used only for demonstration and testing. Synthetic events are never represented as real
            endpoint telemetry, and running a scenario never writes to the real research database.
          </p>
          {!isDemo && (
            <button
              onClick={() => setMode("demo")}
              className="mt-2 text-xs font-medium text-accent hover:underline"
            >
              Switch app to Demo Mode →
            </button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {SCENARIOS.map((scenario) => (
          <ScenarioCard
            key={scenario.id}
            scenario={scenario}
            onRun={handleRun}
            isRunning={running === scenario.id}
            result={results[scenario.id]}
          />
        ))}
      </div>
    </div>
  );
}
