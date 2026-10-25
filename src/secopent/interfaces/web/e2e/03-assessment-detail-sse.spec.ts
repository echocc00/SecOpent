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

  // The SSE endpoint polls assessment.status and emits on change; the first
  // frame always carries the current status (awaiting_approval right after
  // plan generation) - that proves the event stream is live.
  await expect(page.getByText("Event Stream")).toBeVisible();
  await expect(page.getByText("awaiting_approval").first()).toBeVisible({
    timeout: 8000,
  });

  // Drive the REAL status flow: approve (human-only) then start. The status
  // change to queued is pushed over the same SSE stream.
  const approval = await request.post("/api/approvals", {
    data: {
      assessment_id: assessmentId,
      approved_by: "e2e",
      approved_risks: ["passive", "low", "active", "intrusive"],
    },
  });
  expect(approval.status()).toBe(201);
  const started = await request.post(`/api/assessments/${assessmentId}/start`, {
    data: { actor_role: "human" },
  });
  expect([200, 202]).toContain(started.status());
  // The execution starts immediately and (with no reachable scan target in
  // the e2e environment) lands on a terminal status fast - the QUEUED tick
  // can be shorter than the SSE poll interval, so accept any post-approval
  // status. What this proves: the state transition reached the client over
  // the SSE stream.
  await expect(
    page
      .locator("li")
      .filter({ hasText: /queued|running|failed|completed/ })
      .first(),
  ).toBeVisible({ timeout: 10000 });
});
