import { apiClient } from "./client";

export const getVulnerabilities = (assetId) => {
  const query = assetId
    ? `?asset_id=${encodeURIComponent(assetId)}`
    : "";

  return apiClient(`/api/vulnerabilities${query}`);
};