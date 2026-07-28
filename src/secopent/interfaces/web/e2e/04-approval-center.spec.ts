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

  // Wait for the rejection to leave the pending list, then poll the audit
  // chain (the audit commit lands just after the response, so poll for it).
  await expect(page.getByText(assessmentId)).toHaveCount(0);
  await expect
    .poll(
      async () => {
        const events = await (await request.get("/api/audit/events")).json();
        return events.some(
          (e: { action: string; resource_id: string }) =>
            e.action === "approval.rejected" && e.resource_id === assessmentId,
        );
      },
      { timeout: 10000 },
    )
    .toBeTruthy();
});
