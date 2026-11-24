import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { apiClient, getStoredToken, setStoredToken, UNAUTHORIZED_EVENT } from "../api/client.js";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [token, setToken] = useState(() => getStoredToken());
  const [username, setUsername] = useState(null);
  const [role, setRole] = useState(null);
  const [profileError, setProfileError] = useState(false);
  const [profileAttempt, setProfileAttempt] = useState(0);

  useEffect(() => {
    const onUnauthorized = () => {
      setToken(null);
      setUsername(null);
      setRole(null);
    };
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
  }, []);

  // After a page reload: restore the user name and validate the stored token.
  useEffect(() => {
    if (!token || username) return;
    setProfileError(false);
    apiClient
      .get("/api/auth/me")
      .then((r) => {
        setUsername(r.data.username);
        setRole(r.data.role);
      })
      // A 401 already signs the user out (see api/client.js); anything else is
      // a network/server problem the UI must say out loud, not leave blank.
      .catch((err) => setProfileError(err?.response?.status !== 401));
  }, [token, username, profileAttempt]);

  const login = useCallback(async (user, password) => {
    const response = await apiClient.post("/api/auth/login", { username: user, password });
    setStoredToken(response.data.access_token);
    setToken(response.data.access_token);
    setUsername(response.data.username);
    setRole(response.data.role);
  }, []);

  const logout = useCallback(async () => {
    try {
      await apiClient.post("/api/auth/logout");
    } catch {
      // Already expired or backend unreachable — still sign out locally.
    }
    setStoredToken(null);
    setToken(null);
    setUsername(null);
    setRole(null);
  }, []);

  const value = useMemo(
    () => ({
      isAuthenticated: !!token,
      username,
      role,
      isAdmin: role === "admin",
      profileError,
      retryProfile: () => setProfileAttempt((n) => n + 1),
      login,
      logout,
    }),
    [token, username, role, profileError, login, logout]
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
}
