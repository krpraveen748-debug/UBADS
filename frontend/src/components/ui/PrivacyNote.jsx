import { ShieldCheck } from "lucide-react";

/** Compact privacy disclosure reused in Settings and Endpoint Enrollment.
 * Deliberately does not claim an absolute guarantee — only states what is
 * and isn't collected, matching log-collector's documented privacy scope. */
export default function PrivacyNote({ className = "" }) {
  return (
    <div className={`flex gap-3 rounded-lg border border-surface-border bg-surface-raised/50 p-3 ${className}`}>
      <ShieldCheck className="h-4 w-4 text-accent shrink-0 mt-0.5" strokeWidth={1.75} />
      <div>
        <p className="text-xs font-medium text-slate-300">Privacy-first telemetry</p>
        <p className="text-xs text-slate-500 mt-1">
          UBADS collects only the security/activity metadata required for behavioral analysis. It does not collect
          passwords, keystrokes, private messages, screenshots, document contents, or browser passwords/cookies.
        </p>
      </div>
    </div>
  );
}
