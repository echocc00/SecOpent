import { test, expect, seedAssessmentWithPlan } from "./fixtures";

test("dashboard shows recent assessments and quick actions", async ({ page, request }) => {
  const { assessmentId } = await seedAssessmentWithPlan(request);
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  await expect(page.getByRole("button", { name: "New Assessment" })).toBeVisible();
  await expect(page.getByText("Recent Assessments")).toBeVisible();
  // The seeded assessment appears in the recent list.
  await expect(page.getByText(assessmentId).first()).toBeVisible();
});
