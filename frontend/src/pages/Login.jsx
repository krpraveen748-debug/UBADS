import { Lock } from "lucide-react";
import { useState } from "react";
import { registerAccount } from "../api/portal.js";
import { useAuth } from "../auth/AuthContext.jsx";

function loginErrorMessage(err) {
  const status = err?.response?.status;
  if (status === 401) return "Invalid username or password.";
  if (status === 429) return "Too many failed attempts. Please wait and try again.";
  if (!err?.response) return "Cannot reach the UBADS backend. Check the server address and your connection.";
  return "Sign-in failed. Please try again.";
}

function registerErrorMessage(err) {
  const status = err?.response?.status;
  if (!err?.response) return "Cannot reach the UBADS backend. Check the server address and your connection.";
  if (status === 429) return "Too many registrations from this address. Please try again later.";
  if (status === 403) return "Self-registration is turned off on this server.";
  const detail = err.response.data?.detail;
  if (Array.isArray(detail) && detail.length) return detail.map((d) => d.msg.replace(/^Value error, /, "")).join(" ");
  if (typeof detail === "string") return detail;
  return "Registration failed. Please try again.";
}

const INPUT =
  "mt-1 w-full bg-surface border border-surface-border rounded-md px-3 py-2 text-sm text-slate-200 focus:outline-none focus:ring-1 focus:ring-accent/50";

export default function Login() {
  const { login } = useAuth();
  const [mode, setMode] = useState("signin"); // "signin" | "register"
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [organization, setOrganization] = useState("");
  const [error, setError] = useState(null);
  const [notice, setNotice] = useState(null);
  const [busy, setBusy] = useState(false);

  function switchMode(next) {
    setMode(next);
    setError(null);
    setNotice(null);
    setPassword("");
  }

  async function onSubmit(e) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (mode === "register") {
        await registerAccount({ username: username.trim(), password, email: email.trim(), full_name: fullName.trim(), organization: organization.trim() });
        setMode("signin");
        setNotice("Account created. Sign in to request access to the UBADS agent.");
        setPassword("");
      } else {
        await login(username, password);
      }
    } catch (err) {
      setError(mode === "register" ? registerErrorMessage(err) : loginErrorMessage(err));
      setPassword("");
    } finally {
      setBusy(false);
    }
  }

  const registering = mode === "register";

  return (
    <div className="min-h-screen bg-surface flex items-center justify-center p-6">
      <form
        onSubmit={onSubmit}
        className="w-full max-w-sm rounded-lg border border-surface-border bg-surface-raised/60 p-6 space-y-4"
      >
        <div className="flex items-center gap-2">
          <Lock className="h-4 w-4 text-accent" />
          <h1 className="text-base font-semibold text-slate-100">{registering ? "UBADS — Create account" : "UBADS — Sign in"}</h1>
        </div>

        {registering && (
          <>
            <label className="block text-xs text-slate-400">
              Full name
              <input value={fullName} onChange={(e) => setFullName(e.target.value)} autoComplete="name" required maxLength={120} className={INPUT} />
            </label>
            <label className="block text-xs text-slate-400">
              Email
              <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" required className={INPUT} />
            </label>
            <label className="block text-xs text-slate-400">
              Organization
              <input value={organization} onChange={(e) => setOrganization(e.target.value)} autoComplete="organization" required minLength={2} maxLength={120} className={INPUT} />
            </label>
          </>
        )}

        <label className="block text-xs text-slate-400">
          Username
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            required
            className={INPUT}
          />
        </label>
        <label className="block text-xs text-slate-400">
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete={registering ? "new-password" : "current-password"}
            required
            minLength={registering ? 12 : undefined}
            className={INPUT}
          />
          {registering && <span className="mt-1 block text-[11px] text-slate-500">At least 12 characters.</span>}
        </label>

        {notice && (
          <p role="status" className="text-xs text-status-ok">
            {notice}
          </p>
        )}
        {error && (
          <p role="alert" className="text-xs text-status-danger">
            {error}
          </p>
        )}
        <button
          type="submit"
          disabled={busy}
          className="w-full rounded-md bg-accent/10 border border-accent/30 text-accent text-sm font-medium px-4 py-2 hover:bg-accent/20 disabled:opacity-50"
        >
          {registering ? (busy ? "Creating account..." : "Create account") : busy ? "Signing in..." : "Sign in"}
        </button>
        <p className="text-center text-xs text-slate-500">
          {registering ? "Already have an account?" : "Need an account?"}{" "}
          <button type="button" onClick={() => switchMode(registering ? "signin" : "register")} className="text-accent hover:underline">
            {registering ? "Sign in" : "Create one"}
          </button>
        </p>
      </form>
    </div>
  );
}
