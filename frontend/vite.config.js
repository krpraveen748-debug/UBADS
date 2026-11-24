import { existsSync, rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import react from "@vitejs/plugin-react";
import { defineConfig, loadEnv } from "vite";

const frontendRoot = dirname(fileURLToPath(import.meta.url));

// Phase 14A — strips the local development installer from production
// output. Vite normally copies `public/` verbatim; without this, the
// unsigned development artifact would ship in the production bundle even
// though endpoint packages must be issued through the authenticated API.
// This plugin only touches the `vite build` output.
function stripLocalDevDownloadsFromProductionBuild() {
  return {
    name: "strip-local-dev-downloads",
    apply: "build",
    closeBundle() {
      const outDir = resolve(frontendRoot, "dist", "downloads");
      if (existsSync(outDir)) {
        rmSync(outDir, { recursive: true, force: true });
      }
    },
  };
}

export default defineConfig(({ command, mode }) => {
  const env = loadEnv(mode, frontendRoot, "VITE_");
  const apiBaseUrl = env.VITE_API_BASE_URL?.trim();
  if (command === "build") {
    let parsedApiUrl;
    try {
      parsedApiUrl = new URL(apiBaseUrl || "");
    } catch {
      throw new Error("Production builds require VITE_API_BASE_URL to be a valid HTTPS API origin.");
    }
    if (
      parsedApiUrl.protocol !== "https:" ||
      !parsedApiUrl.hostname ||
      parsedApiUrl.username ||
      parsedApiUrl.password ||
      parsedApiUrl.pathname !== "/" ||
      parsedApiUrl.search ||
      parsedApiUrl.hash
    ) {
      throw new Error("Production builds require VITE_API_BASE_URL to be a valid HTTPS API origin.");
    }
  }

  return {
    plugins: [react(), stripLocalDevDownloadsFromProductionBuild()],
    server: {
      port: 5173,
    },
  };
});
