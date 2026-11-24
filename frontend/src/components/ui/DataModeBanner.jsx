import { FlaskConical, Radio } from "lucide-react";
import { useDataMode } from "../../context/DataModeContext.jsx";

/**
 * Large, unmissable indicator of which data mode is currently active.
 * Used at the top of pages that display data (Overview, Demo Lab,
 * Anomalies, Behavioral Activity) so it is never ambiguous whether what's
 * on screen is real endpoint telemetry or synthetic demonstration data.
 */
export default function DataModeBanner({ description }) {
  const { isLive } = useDataMode();

  if (isLive) {
    return (
      <div className="flex items-center gap-3 rounded-lg border border-accent/30 bg-accent/5 px-4 py-3">
        <Radio className="h-4 w-4 text-accent shrink-0" strokeWidth={1.75} />
        <div>
          <p className="text-sm font-semibold text-accent tracking-wide">LIVE ENDPOINT DATA</p>
          <p className="text-xs text-slate-500 mt-0.5">
            {description || "Data on this page comes only from real, authorized Windows endpoint collection."}
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex items-center gap-3 rounded-lg border border-status-warn/30 bg-status-warn/5 px-4 py-3">
      <FlaskConical className="h-4 w-4 text-status-warn shrink-0" strokeWidth={1.75} />
      <div>
        <p className="text-sm font-semibold text-status-warn tracking-wide">DEMO / SYNTHETIC DATA</p>
        <p className="text-xs text-slate-500 mt-0.5">
          {description || "Synthetic data for demonstration only. No real endpoint data is affected or shown."}
        </p>
      </div>
    </div>
  );
}
