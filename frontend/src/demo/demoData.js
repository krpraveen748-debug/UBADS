/**
 * Isolated synthetic demo/test data layer.
 *
 * EVERYTHING in this file is fabricated for demonstration purposes only.
 * It is never written to the real SQLite database, never sent to the
 * backend, and never merged with a LIVE-mode API response. Every
 * component that renders data from this file MUST also render a visible
 * "DEMO DATA" / "SYNTHETIC TEST" label alongside it — see
 * src/components/ui/DataModeBanner.jsx and src/components/ui/Badge.jsx.
 */

export const DEMO_USERNAME = "demo_user";
export const DEMO_ENDPOINT = "DEMO-PC-01";

export const demoUserBaseline = {
  username: DEMO_USERNAME,
  endpoint: DEMO_ENDPOINT,
  observedDays: 5,
  events: 342,
  typicalLoginWindow: "08:30–10:15",
  typicalActivityHours: "08:00–18:00",
  commonCategories: ["Authentication", "File", "Process"],
  baselineStatus: "Building",
  mlReadiness: "Illustrative only — not a real readiness result",
};

// A plausible (fabricated) events-per-hour curve peaking during a typical
// workday, purely to illustrate what the Behavioral Activity chart will
// look like once real data exists.
export const demoHourlyActivity = [
  { hour: "00:00", events: 0 },
  { hour: "01:00", events: 0 },
  { hour: "02:00", events: 1 },
  { hour: "03:00", events: 0 },
  { hour: "04:00", events: 0 },
  { hour: "05:00", events: 0 },
  { hour: "06:00", events: 0 },
  { hour: "07:00", events: 2 },
  { hour: "08:00", events: 9 },
  { hour: "09:00", events: 14 },
  { hour: "10:00", events: 11 },
  { hour: "11:00", events: 8 },
  { hour: "12:00", events: 4 },
  { hour: "13:00", events: 7 },
  { hour: "14:00", events: 10 },
  { hour: "15:00", events: 12 },
  { hour: "16:00", events: 9 },
  { hour: "17:00", events: 6 },
  { hour: "18:00", events: 2 },
  { hour: "19:00", events: 1 },
  { hour: "20:00", events: 0 },
  { hour: "21:00", events: 0 },
  { hour: "22:00", events: 0 },
  { hour: "23:00", events: 0 },
];

export const demoRecentEvents = [
  {
    id: "demo-1",
    time: "08:41",
    user: DEMO_USERNAME,
    computer: DEMO_ENDPOINT,
    event: "Successful Login",
    category: "Authentication",
    source: "Windows Security",
    status: "Normal",
  },
  {
    id: "demo-2",
    time: "08:42",
    user: DEMO_USERNAME,
    computer: DEMO_ENDPOINT,
    event: "Process Started (notepad.exe)",
    category: "Process",
    source: "Windows Security",
    status: "Normal",
  },
  {
    id: "demo-3",
    time: "09:15",
    user: DEMO_USERNAME,
    computer: DEMO_ENDPOINT,
    event: "File Accessed (report.docx)",
    category: "File",
    source: "Windows Security",
    status: "Normal",
  },
  {
    id: "demo-4",
    time: "17:58",
    user: DEMO_USERNAME,
    computer: DEMO_ENDPOINT,
    event: "Logoff",
    category: "Authentication",
    source: "Windows Security",
    status: "Normal",
  },
  {
    id: "demo-5",
    time: "02:13",
    user: DEMO_USERNAME,
    computer: DEMO_ENDPOINT,
    event: "Successful Login",
    category: "Authentication",
    source: "Windows Security",
    status: "Unusual",
  },
];

export const demoAnomalySummary = { total: 3, high: 1, medium: 1, low: 1 };

export const demoAnomalies = [
  {
    id: "demo-anomaly-1",
    timestamp: "02:13",
    user: DEMO_USERNAME,
    endpoint: DEMO_ENDPOINT,
    type: "Unusual Login Time",
    risk: "High",
    score: 0.91,
    reason: "Activity occurred outside the learned behavioral window (typical 08:30–10:30).",
    status: "Simulated",
  },
  {
    id: "demo-anomaly-2",
    timestamp: "13:04",
    user: DEMO_USERNAME,
    endpoint: DEMO_ENDPOINT,
    type: "Unusual Process Activity",
    risk: "Medium",
    score: 0.64,
    reason: "Execution of a process not previously observed for this user (powershell_encoded_cmd.exe).",
    status: "Simulated",
  },
  {
    id: "demo-anomaly-3",
    timestamp: "15:47",
    user: DEMO_USERNAME,
    endpoint: DEMO_ENDPOINT,
    type: "Unusual Activity Burst",
    risk: "Low",
    score: 0.38,
    reason: "142 events recorded within a 3-minute window versus a typical rate of ~15/hour.",
    status: "Simulated",
  },
];
