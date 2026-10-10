import { apiClient } from "./client";

export const optimizeInvestment = (budget) => {
  return apiClient("/api/optimize", {
    method: "POST",
    body: JSON.stringify({
      budget_inr: Number(budget),
    }),
  });
};