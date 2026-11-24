/**
 * Backend API endpoints. Requests pass through the shared authenticated
 * client; pages render only values returned by the backend.
 */

import { apiClient } from "./client.js";

export async function getHealth() {
  const response = await apiClient.get("/health");
  return response.data;
}

// -- Prepared, not yet implemented on the backend --

export async function getEvents(params = {}) {
  const response = await apiClient.get("/api/events", { params });
  return response.data;
}

export async function getEventDetail(eventId) {
  const response = await apiClient.get(`/api/events/${eventId}`);
  return response.data;
}

export async function getUsers() {
  const response = await apiClient.get("/api/users");
  return response.data;
}

export async function getBaselines() {
  const response = await apiClient.get("/api/users/baselines");
  return response.data;
}

export async function getAnomalies(params = {}) {
  const response = await apiClient.get("/api/anomalies", { params });
  return response.data;
}

export async function getAnomalyModelStatus() {
  const response = await apiClient.get("/api/ml/anomaly-status");
  return response.data;
}

export async function trainAnomalyModels() {
  const response = await apiClient.post("/api/ml/train-anomaly-models");
  return response.data;
}

export async function getCollectionStatus() {
  const response = await apiClient.get("/api/ml/collection-status");
  return response.data;
}

export async function getSyntheticExperimentSummary() {
  const response = await apiClient.get("/api/ml/synthetic-experiment");
  return response.data;
}

export async function getSyntheticExperimentSamples(params = {}) {
  const response = await apiClient.get("/api/ml/synthetic-experiment/samples", { params });
  return response.data;
}

export async function getDataQualityReport() {
  const response = await apiClient.get("/api/reports/data-quality");
  return response.data;
}

export async function getEndpointStatus() {
  const response = await apiClient.get("/api/endpoints/status");
  return response.data;
}

// Phase 14 — every enrolled endpoint's safe identity fields (never a
// credential). Used by the Events page to let a real, per-endpoint
// (credentialed) identity filter events, not just a self-reported
// computer name — see EndpointEnrollment.jsx for the enrollment flow
// itself and backend/app/api/endpoint_identity.py for the route.
export async function getEndpoints() {
  const response = await apiClient.get("/api/endpoints");
  return response.data;
}

// -- Phase 17: administrator endpoint-request management (admin session only) --

export async function getAdminEndpointRequests(params = {}) {
  const response = await apiClient.get("/api/admin/endpoint-requests", { params });
  return response.data;
}

export async function getAdminEndpointRequest(id) {
  const response = await apiClient.get(`/api/admin/endpoint-requests/${encodeURIComponent(id)}`);
  return response.data;
}

export async function approveEndpointRequest(id, body = {}) {
  const response = await apiClient.post(`/api/admin/endpoint-requests/${encodeURIComponent(id)}/approve`, body);
  return response.data;
}

export async function rejectEndpointRequest(id, reason) {
  const response = await apiClient.post(`/api/admin/endpoint-requests/${encodeURIComponent(id)}/reject`, { reason });
  return response.data;
}

export async function revokeEndpointRequest(id, reason) {
  const response = await apiClient.post(`/api/admin/endpoint-requests/${encodeURIComponent(id)}/revoke`, { reason });
  return response.data;
}
