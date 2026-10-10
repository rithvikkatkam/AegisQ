import { apiClient } from "./client";

export const getAssets = () => {
  return apiClient("/api/assets");
};