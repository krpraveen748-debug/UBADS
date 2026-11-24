import axios from "axios";

// The ONLY place the backend URL is read from. Every API call in this
// project must go through this client — never construct a URL with
// "localhost" or a hard-coded host directly in a component.
const configuredApiBaseUrl = import.meta.env.VITE_API_BASE_URL?.trim();
export const API_BASE_URL =
  configuredApiBaseUrl || (import.meta.env.DEV ? "http://127.0.0.1:8000" : "");

if (!API_BASE_URL) {
  throw new Error("VITE_API_BASE_URL must be configured for production builds.");
}

// The dashboard session token is issued by the backend at login and kept
// only for the lifetime of the browser tab (sessionStorage). Nothing is
// hard-coded here, and it is never written to localStorage.
const TOKEN_KEY = "ubads.dashboardToken";
export const UNAUTHORIZED_EVENT = "ubads:unauthorized";

export function getStoredToken() {
  try {
    return window.sessionStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setStoredToken(token) {
  try {
    if (token) window.sessionStorage.setItem(TOKEN_KEY, token);
    else window.sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    // sessionStorage unavailable — the session simply won't survive a reload.
  }
}

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 5000,
});

apiClient.interceptors.request.use((config) => {
  const token = getStoredToken();
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    // An expired/revoked session anywhere sends the user back to sign-in.
    // (A failed login is also a 401, but there is no stored token yet.)
    if (error?.response?.status === 401 && getStoredToken()) {
      setStoredToken(null);
      window.dispatchEvent(new Event(UNAUTHORIZED_EVENT));
    }
    return Promise.reject(error);
  }
);
