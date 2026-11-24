import { createContext, useContext, useEffect, useMemo, useState } from "react";

/**
 * Global LIVE / DEMO data-mode switch.
 *
 * This is the single source of truth the whole app reads to decide whether
 * a page should call the real backend API or the isolated demo/ data layer
 * (see src/demo/). Nothing else may independently decide "am I showing
 * live or synthetic data" — that would risk the two getting mixed, which
 * this project's instructions explicitly forbid.
 *
 * Persisted to localStorage only for UI convenience (remembering the last
 * mode across reloads) — it has no effect on any backend data and never
 * writes anything to the real database.
 */

export const DATA_MODES = { LIVE: "live", DEMO: "demo" };
const STORAGE_KEY = "ubads.dataMode";

const DataModeContext = createContext(null);

export function DataModeProvider({ children }) {
  const [mode, setMode] = useState(() => {
    try {
      const stored = window.localStorage.getItem(STORAGE_KEY);
      return stored === DATA_MODES.DEMO ? DATA_MODES.DEMO : DATA_MODES.LIVE;
    } catch {
      return DATA_MODES.LIVE;
    }
  });

  useEffect(() => {
    try {
      window.localStorage.setItem(STORAGE_KEY, mode);
    } catch {
      // localStorage unavailable (private browsing, etc.) — mode still
      // works for this session, just doesn't persist. Non-fatal.
    }
  }, [mode]);

  const value = useMemo(
    () => ({
      mode,
      isLive: mode === DATA_MODES.LIVE,
      isDemo: mode === DATA_MODES.DEMO,
      setMode,
      toggleMode: () => setMode((m) => (m === DATA_MODES.LIVE ? DATA_MODES.DEMO : DATA_MODES.LIVE)),
    }),
    [mode]
  );

  return <DataModeContext.Provider value={value}>{children}</DataModeContext.Provider>;
}

export function useDataMode() {
  const ctx = useContext(DataModeContext);
  if (!ctx) throw new Error("useDataMode must be used within a DataModeProvider");
  return ctx;
}
