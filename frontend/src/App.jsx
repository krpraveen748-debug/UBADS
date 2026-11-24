import { Route, Routes } from "react-router-dom";
import { useAuth } from "./auth/AuthContext.jsx";
import Layout from "./components/layout/Layout.jsx";
import Anomalies from "./pages/Anomalies.jsx";
import DemoLab from "./pages/DemoLab.jsx";
import EndpointRequests from "./pages/EndpointRequests.jsx";
import EndpointEnrollment from "./pages/EndpointEnrollment.jsx";
import Events from "./pages/Events.jsx";
import Login from "./pages/Login.jsx";
import UserPortal from "./pages/portal/UserPortal.jsx";
import LiveMonitoring from "./pages/LiveMonitoring.jsx";
import Overview from "./pages/Overview.jsx";
import Reports from "./pages/Reports.jsx";
import Settings from "./pages/Settings.jsx";
import UsersBaselines from "./pages/UsersBaselines.jsx";

const PAGE_META = {
  "/": { title: "Overview", subtitle: "Security command center" },
  "/live-monitoring": { title: "Live Monitoring", subtitle: "Real-time collector and endpoint status" },
  "/events": { title: "Events", subtitle: "Real collected Windows Security events" },
  "/users": { title: "Users & Baselines", subtitle: "Per-user behavioral coverage" },
  "/anomalies": { title: "Anomalies", subtitle: "Detected behavioral anomalies" },
  "/demo-lab": { title: "Demo Lab", subtitle: "Scenario-driven detection walkthroughs" },
  "/reports": { title: "Reports", subtitle: "Data-quality and research readiness reports" },
  "/endpoint-requests": { title: "Endpoint Requests", subtitle: "Review and approve agent installation requests" },
  "/endpoint-enrollment": { title: "Endpoint Enrollment", subtitle: "Install the UBADS agent on an authorized endpoint" },
  "/settings": { title: "Settings", subtitle: "Backend connection and configuration" },
};

function Page({ path, children }) {
  const meta = PAGE_META[path];
  return (
    <Layout title={meta.title} subtitle={meta.subtitle}>
      {children}
    </Layout>
  );
}

const ROUTES = [
  { path: "/", element: <Overview /> },
  { path: "/live-monitoring", element: <LiveMonitoring /> },
  { path: "/events", element: <Events /> },
  { path: "/users", element: <UsersBaselines /> },
  { path: "/anomalies", element: <Anomalies /> },
  { path: "/demo-lab", element: <DemoLab /> },
  { path: "/reports", element: <Reports /> },
  { path: "/endpoint-requests", element: <EndpointRequests /> },
  { path: "/endpoint-enrollment", element: <EndpointEnrollment /> },
  { path: "/settings", element: <Settings /> },
];

export default function App() {
  const { isAuthenticated, role, logout, profileError, retryProfile } = useAuth();
  if (!isAuthenticated) return <Login />;
  if (role === null && profileError) {
    return (
      <div className="min-h-screen bg-surface flex items-center justify-center p-6">
        <div role="alert" className="max-w-md rounded-lg border border-surface-border bg-surface-raised/60 p-6 space-y-3 text-center">
          <h1 className="text-base font-semibold text-slate-100">Cannot reach the UBADS backend</h1>
          <p className="text-sm text-slate-400">Your sign-in is still valid, but your account details could not be loaded.</p>
          <div className="flex justify-center gap-2">
            <button onClick={retryProfile} className="rounded-md border border-accent/30 bg-accent/10 px-3 py-1.5 text-xs font-medium text-accent hover:bg-accent/20">
              Retry
            </button>
            <button onClick={logout} className="rounded-md border border-surface-border px-3 py-1.5 text-xs text-slate-300 hover:bg-surface-raised">
              Sign out
            </button>
          </div>
        </div>
      </div>
    );
  }
  if (role === null) return <div className="min-h-screen bg-surface" />; // role still loading after a reload
  if (role !== "admin") return <UserPortal />; // normal accounts: portal only, no admin routes exist for them
  return (
    <Routes>
      {ROUTES.map(({ path, element }) => (
        <Route
          key={path}
          path={path}
          element={
            <Page path={path}>
              {element}
            </Page>
          }
        />
      ))}
    </Routes>
  );
}
