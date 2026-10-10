import { apiClient } from "./client";

export const getHealth = () => {
  return apiClient("/api/health");
};