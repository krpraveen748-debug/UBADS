import { useCallback, useEffect, useState } from "react";

/**
 * Shared data-fetching hook for every LIVE-mode page.
 *
 * Distinguishes three real states rather than collapsing everything into
 * a generic "error":
 *   - loading:      request in flight
 *   - notAvailable: backend reached, but this route returned 404 — i.e.
 *                   the endpoint hasn't been built yet. Render "not
 *                   available yet", never a fabricated empty/zero value.
 *   - unreachable:  the backend could not be reached at all (network
 *                   error, refused connection, timeout). Render
 *                   "backend unavailable" with a way to retry.
 *   - data:         the real response body, only ever set from an actual
 *                   backend reply.
 *
 * `enabled: false` skips fetching entirely (used to avoid calling the
 * backend at all while the page is in DEMO mode).
 */
export function useApiResource(fetcher, deps = [], { enabled = true } = {}) {
  const [state, setState] = useState({
    loading: enabled,
    data: null,
    notAvailable: false,
    unreachable: false,
    errorMessage: null,
  });

  const load = useCallback(() => {
    if (!enabled) {
      setState({ loading: false, data: null, notAvailable: false, unreachable: false, errorMessage: null });
      return;
    }
    setState((prev) => ({ ...prev, loading: true, errorMessage: null }));
    fetcher()
      .then((data) => {
        setState({ loading: false, data, notAvailable: false, unreachable: false, errorMessage: null });
      })
      .catch((err) => {
        const status = err?.response?.status;
        if (status === 404) {
          setState({ loading: false, data: null, notAvailable: true, unreachable: false, errorMessage: null });
        } else {
          setState({
            loading: false,
            data: null,
            notAvailable: false,
            unreachable: true,
            errorMessage: err?.message || "Request failed",
          });
        }
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, ...deps]);

  useEffect(() => {
    load();
  }, [load]);

  return { ...state, reload: load };
}
