/**
 * Demo Lab scenarios.
 *
 * Each scenario is a hand-authored, deterministic, purely illustrative
 * walkthrough — NOT a call to any real ML model (Isolation Forest or
 * otherwise; no anomaly-detection model exists in this project yet). This
 * file exists so the demo can show what an anomaly explanation would look
 * like once a real model is trained. Running a scenario never writes to
 * the real SQLite database and never affects LIVE-mode data.
 */

import { DEMO_ENDPOINT, DEMO_USERNAME } from "../demoData.js";

export const SCENARIOS = [
  {
    id: "unusual-login-time",
    title: "Unusual Login Time",
    category: "Authentication",
    normalLabel: "Typical login window",
    normalDescription: "08:30 – 10:30",
    simulatedLabel: "Simulated login time",
    simulatedDescription: "02:13 AM",
    result: {
      anomalyType: "Unusual Login Time",
      riskLevel: "High",
      reason:
        "Login occurred well outside the learned typical window (08:30–10:30) for this user, at an hour with no prior observed activity.",
    },
  },
  {
    id: "unusual-process-activity",
    title: "Unusual Process Activity",
    category: "Process",
    normalLabel: "Typical processes",
    normalDescription: "chrome.exe, outlook.exe, explorer.exe, notepad.exe",
    simulatedLabel: "Simulated process",
    simulatedDescription: "powershell_encoded_cmd.exe (previously unseen for this user)",
    result: {
      anomalyType: "Unusual Process Activity",
      riskLevel: "High",
      reason:
        "A process never previously observed for this user was launched, with characteristics (encoded command execution) commonly associated with obfuscated scripting.",
    },
  },
  {
    id: "unusual-activity-burst",
    title: "Unusual Activity Burst",
    category: "Cross-category",
    normalLabel: "Typical activity rate",
    normalDescription: "~15 events / hour",
    simulatedLabel: "Simulated burst",
    simulatedDescription: "142 events within 3 minutes",
    result: {
      anomalyType: "Unusual Activity Burst",
      riskLevel: "Medium",
      reason:
        "Event volume in a short window far exceeds this user's typical hourly rate, consistent with automated or bulk activity rather than normal interactive use.",
    },
  },
  {
    id: "unusual-device-activity",
    title: "Unusual Device Activity",
    category: "Device",
    normalLabel: "Typical device activity",
    normalDescription: "No removable storage devices typically connected",
    simulatedLabel: "Simulated device event",
    simulatedDescription: "New USB mass-storage device connected, followed by 40 file accesses in 2 minutes",
    result: {
      anomalyType: "Unusual Device Activity",
      riskLevel: "Medium",
      reason:
        "A device class not previously seen for this user was connected, immediately followed by a burst of file activity — a pattern consistent with bulk data transfer.",
    },
  },
  {
    id: "combined-behavioral-deviation",
    title: "Combined Behavioral Deviation",
    category: "Cross-category",
    normalLabel: "Typical pattern",
    normalDescription: "Deviations, when they occur, are usually isolated to one category",
    simulatedLabel: "Simulated combination",
    simulatedDescription: "Off-hours login + unrecognized process + high-volume file access, all within one session",
    result: {
      anomalyType: "Combined Behavioral Deviation",
      riskLevel: "High",
      reason:
        "Multiple independent deviations occurred together in a single session. Each alone might be low-confidence; occurring together substantially raises the combined risk assessment.",
    },
  },
];

/**
 * Deterministic, scripted "run" — returns the scenario's pre-authored
 * result annotated with user/endpoint/timestamp. This is a simulation of
 * what an explanation would look like, not a real model inference.
 */
export function runScenario(scenario) {
  return {
    scenarioId: scenario.id,
    title: scenario.title,
    user: DEMO_USERNAME,
    endpoint: DEMO_ENDPOINT,
    ranAt: new Date().toISOString(),
    normalLabel: scenario.normalLabel,
    normalDescription: scenario.normalDescription,
    simulatedLabel: scenario.simulatedLabel,
    simulatedDescription: scenario.simulatedDescription,
    ...scenario.result,
  };
}
