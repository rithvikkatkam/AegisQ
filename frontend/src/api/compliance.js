import { apiClient } from "./client";

export const getComplianceMapping = () => {
  return apiClient("/api/compliance/mapping");
};