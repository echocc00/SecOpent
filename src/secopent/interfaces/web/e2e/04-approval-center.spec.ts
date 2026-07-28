import { test, expect, seedAssessmentWithPlan } from "./fixtures";

test("approve: pending -> approved, moves to history", async ({ page, request }) => {
  const { assessmentId } = await seedAssessmentWithPlan(request);
  await page.goto("/approvals");
  await expect(page.getByRole("heading", { name: "Approval Center" })).toBeVisible();

  // Open the pending row's drawer and approve
  await page.getByText(assessmentId).first().click();
  await page.getByRole("button", { name: "Approve", exact: true }).click();

  // Leaves the pending list
  await expect(page.getByText(assessmentId)).toHaveCount(0);
  // Appears in history as approved
  await page.getByRole("tab", { name: /History/ }).click();
  await expect(page.getByText(assessmentId).first()).toBeVisible();
});

test("reject: pending -> rejected with reason, recorded in audit chain", async ({
  page,
  request,
}) => {
  const { assessmentId } = await seedAssessmentWithPlan(request);
  await page.goto("/approvals");

  await page.getByText(assessmentId).first().click();
  await page.getByPlaceholder("Reason for rejection").fill("scope too broad");
  await page.getByRole("button", { name: "Reject", exact: true }).click();

  // Rejection is recorded in the tamper-evident audit chain
  const audit = await request.get("/api/audit/events");
  const events = await audit.json();
  expect(
    events.some(
      (e: { action: string; resource_id: string }) =>
        e.action === "approval.rejected" && e.resource_id === assessmentId,
    ),
  ).toBeTruthy();
});
