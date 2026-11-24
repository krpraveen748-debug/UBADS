import { getHealth } from "../api/endpoints.js";
import { useApiResource } from "./useApiResource.js";

/** Shared, real backend connectivity check (GET /health) — used by the
 * Topbar badge, Overview, Live Monitoring, and Settings so "Connected"
 * always means the same verified thing everywhere in the app. */
export function useBackendHealth() {
  return useApiResource(getHealth, []);
}
