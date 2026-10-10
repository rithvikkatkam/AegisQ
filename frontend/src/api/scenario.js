import { apiClient } from "./client";

export const simulateScenario = (controlIds) => {
  return apiClient("/api/scenario/simulate", {
    method: "POST",
    body: JSON.stringify({
      control_ids: controlIds,
    }),
  });
};