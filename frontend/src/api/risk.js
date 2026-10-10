import { apiClient } from "./client";

export const getRiskSummary = () => {
  return apiClient("/api/risk/summary");
};

export const getAssetRisk = (assetId) => {
  return apiClient(`/api/risk/assets/${assetId}`);
};