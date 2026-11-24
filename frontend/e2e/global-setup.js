// Starts a fully ISOLATED UBADS stack for the browser tests:
//   - a throwaway SQLite database inside the OS temp directory (seeded with
//     test-only accounts whose passwords are random per run),
//   - a backend on 127.0.0.1:8801 and the Vite dev server on 127.0.0.1:5801.
// It never reads config/.env, never touches data/app.db, and uses neither the
// real backend on port 8000 nor any real endpoint credential.
import { spawn, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const frontendDir = path.resolve(here, "..");
const projectRoot = path.resolve(frontendDir, "..");
const python = path.join(projectRoot, ".venv", "Scripts", "python.exe");

export const BACKEND_PORT = 8801;
export const FRONTEND_PORT = 5801;

async function waitFor(url, label, ms = 90000) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(url);
      if (r.ok) return;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`${label} did not start at ${url}`);
}

function killTree(child) {
  if (child?.pid) spawnSync("taskkill", ["/PID", String(child.pid), "/T", "/F"], { stdio: "ignore" });
}

export default async function globalSetup() {
  for (const port of [BACKEND_PORT, FRONTEND_PORT]) {
    const inUse = await fetch(`http://127.0.0.1:${port}/`).then(() => true, () => false);
    if (inUse) throw new Error(`Port ${port} is already in use; refusing to run browser tests against it.`);
  }

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "ubads-e2e-"));
  const dbFile = path.join(tmp, "e2e.db");
  const rand = () => `E2e-${crypto.randomBytes(12).toString("base64url")}`;
  const creds = {
    admin: { username: "e2e-admin", password: rand() },
    user: { username: "e2e-user", password: rand() },
    backend: `http://127.0.0.1:${BACKEND_PORT}`,
    frontend: `http://127.0.0.1:${FRONTEND_PORT}`,
  };
  // A tiny stand-in for the real installer, so browser tests stay fast and never
  // move the real 39 MB build. The backend's real default location is covered
  // by a backend test (test_default_installer_location_is_the_real_build_output).
  const installerStub = path.join(tmp, "UBADS-Agent-Setup.exe");
  creds.installerContent = "UBADS-E2E-STUB-INSTALLER-NOT-A-REAL-AGENT";
  fs.writeFileSync(installerStub, creds.installerContent);
  const stateFile = path.join(tmp, "state.json");
  fs.writeFileSync(stateFile, JSON.stringify(creds));
  process.env.E2E_STATE_FILE = stateFile; // inherited by test workers

  const backendEnv = {
    ...process.env,
    DATABASE_URL: `sqlite:///${dbFile.replaceAll("\\", "/")}`,
    CORS_ALLOWED_ORIGINS: creds.frontend,
    AGENT_API_KEY: "",
    INSTALLER_PATH: installerStub,
    ENVIRONMENT: "local",
    E2E_ADMIN_USER: creds.admin.username,
    E2E_ADMIN_PASSWORD: creds.admin.password,
    E2E_USER_USER: creds.user.username,
    E2E_USER_PASSWORD: creds.user.password,
  };

  const seed = spawnSync(python, [path.join(here, "seed_e2e_db.py")], { env: backendEnv, cwd: tmp, encoding: "utf-8" });
  if (seed.status !== 0) throw new Error(`Seeding the isolated database failed:\n${seed.stdout}\n${seed.stderr}`);

  const backend = spawn(
    python,
    ["-m", "uvicorn", "app.main:app", "--app-dir", path.join(projectRoot, "backend"), "--host", "127.0.0.1", "--port", String(BACKEND_PORT)],
    { env: backendEnv, cwd: tmp, stdio: "ignore", windowsHide: true }
  );
  const vite = spawn(
    process.execPath,
    [path.join(frontendDir, "node_modules", "vite", "bin", "vite.js"), "--host", "127.0.0.1", "--port", String(FRONTEND_PORT), "--strictPort"],
    { env: { ...process.env, VITE_API_BASE_URL: creds.backend }, cwd: frontendDir, stdio: "ignore", windowsHide: true }
  );

  const teardown = async () => {
    killTree(backend);
    killTree(vite);
    await new Promise((r) => setTimeout(r, 1500));
    fs.rmSync(tmp, { recursive: true, force: true });
  };
  try {
    await waitFor(`${creds.backend}/health`, "isolated backend");
    await waitFor(creds.frontend, "frontend dev server");
  } catch (err) {
    await teardown();
    throw err;
  }
  return teardown;
}
