// User-portal API calls. Every call goes through apiClient (bearer token added
// there); the backend enforces ownership and approval - nothing here is trusted.
import { apiClient } from "./client.js";

export async function registerAccount(body) {
  const r = await apiClient.post("/api/auth/register", body);
  return r.data;
}

export async function getMe() {
  return (await apiClient.get("/api/auth/me")).data;
}

export async function createEndpointRequest(body) {
  return (await apiClient.post("/api/endpoint-requests", body)).data;
}

export async function getMyRequests() {
  return (await apiClient.get("/api/endpoint-requests/my")).data;
}

export async function getMyRequest(id) {
  return (await apiClient.get(`/api/endpoint-requests/${encodeURIComponent(id)}`)).data;
}

export async function getDownloadInfo(id) {
  return (await apiClient.get(`/api/endpoint-requests/${encodeURIComponent(id)}/download-info`)).data;
}

const ENROLLMENT_PACKAGE_FILENAME = /^UBADS-Agent-Setup--ubads1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}\.exe$/;

function enrollmentPackageFilename(response) {
  const disposition = response.headers["content-disposition"] || "";
  const extended = disposition.match(/filename\*\s*=\s*UTF-8''([^;]+)/i);
  const regular = disposition.match(/filename\s*=\s*(?:"([^"]+)"|([^;]+))/i);
  const value = extended?.[1] ?? regular?.[1] ?? regular?.[2]?.trim();
  let filename;
  try {
    filename = decodeURIComponent(value || "");
  } catch {
    filename = "";
  }
  if (!ENROLLMENT_PACKAGE_FILENAME.test(filename)) {
    throw new Error("The installer response did not include a valid enrollment package.");
  }
  return filename;
}

/** Mints and downloads an endpoint-specific package using the signed-in session. */
export async function downloadInstaller(id) {
  const response = await apiClient.post(`/api/endpoint-requests/${encodeURIComponent(id)}/enrollment-package`, null, {
    responseType: "blob",
    timeout: 0, // the installer is tens of MB
  });
  const filename = enrollmentPackageFilename(response);
  const url = URL.createObjectURL(response.data);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

export async function getNotifications(params = {}) {
  return (await apiClient.get("/api/notifications", { params })).data;
}

export async function getUnreadCount() {
  return (await apiClient.get("/api/notifications/unread-count")).data.unread;
}

export async function markNotificationRead(id) {
  return (await apiClient.post(`/api/notifications/${id}/read`)).data;
}

export async function markAllNotificationsRead() {
  return (await apiClient.post("/api/notifications/read-all")).data;
}

/** Turns an axios error into a message safe and useful to show a person. */
export function errorText(err, fallback = "Something went wrong. Please try again.") {
  if (!err?.response) return "Cannot reach the UBADS backend. Check your connection and try again.";
  const detail = err.response.data?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail) && detail.length) return detail.map((d) => d.msg).join(" ");
  return fallback;
}
