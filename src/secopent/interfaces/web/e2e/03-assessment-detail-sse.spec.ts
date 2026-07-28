import { test, expect, seedAssessmentWithPlan } from "./fixtures";

test("assessment detail: plan DAG renders and SSE event stream receives events", async ({
  page,
  request,
}) => {
  const { assessmentId } = await seedAssessmentWithPlan(request);
  await page.goto(`/assessments/${assessmentId}`);

  await expect(page.getByRole("heading", { name: "Assessment" })).toBeVisible();
  // Plan DAG (react-flow) with at least one step node
  await expect(page.locator(".react-flow")).toBeVisible();
  await expect(page.locator(".react-flow__node").first()).toBeVisible();

  // SSE (demo) pushes queued/running/completed -> the event stream fills
  await expect(page.getByText("Event Stream")).toBeVisible();
  await expect(page.getByText("queued").first()).toBeVisible({ timeout: 8000 });
  await expect(page.getByText("completed").first()).toBeVisible({ timeout: 8000 });
});
