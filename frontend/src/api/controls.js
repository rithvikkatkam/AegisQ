import { apiClient } from "./client";

export const getControls = () => {
  return apiClient("/api/controls");
};